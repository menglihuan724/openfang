//! OpenClaw Android Node adapter for the OpenFang channel bridge.
//!
//! Connects to an OpenClaw Gateway as a device node via WebSocket, receiving
//! command requests (screenshot, ui_tree, tap, swipe, etc.) and returning results.
//!
//! Protocol reference: <https://github.com/openclaw/openclaw>
//! Android node reference: <https://github.com/BlueCodeSystems/openclaw-android-node>

use crate::types::{
    ChannelAdapter, ChannelContent, ChannelMessage, ChannelType, ChannelUser,
};
use async_trait::async_trait;
use chrono::Utc;
use futures::{SinkExt, Stream, StreamExt};
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};

const OPENCLAW_PROTOCOL_VERSION: i64 = 3;
const DEFAULT_GATEWAY_PORT: u16 = 18_789;
const MAX_BACKOFF_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Shared bridge handle — lets the kernel send invoke_result frames over the
// WebSocket without owning the socket directly.
// ---------------------------------------------------------------------------

/// Message type for sending frames from the bridge to the WebSocket task.
#[derive(Debug)]
pub enum OpenClawBridgeMsg {
    /// Send a node.invokeResult frame back to the gateway.
    InvokeResult(serde_json::Value),
    /// Signal the connection loop to stop.
    Shutdown,
}

/// Handle for sending messages to the OpenClaw WebSocket connection from
/// outside the connection task. Cloning creates new senders that all feed
/// into the same channel consumed by the WebSocket task.
#[derive(Clone)]
pub struct OpenClawBridgeHandle {
    tx: mpsc::Sender<OpenClawBridgeMsg>,
}

impl OpenClawBridgeHandle {
    /// Send an invoke result frame to the OpenClaw Gateway.
    ///
    /// This is called from `dispatch_message()` in the bridge after the agent
    /// processes an OpenClaw command.
    pub async fn send_invoke_result(&self, frame: serde_json::Value) {
        if let Err(e) = self.tx.send(OpenClawBridgeMsg::InvokeResult(frame)).await {
            error!("OpenClaw: failed to send invoke_result to WS task: {e}");
        }
    }

    /// Signal the connection loop to shut down.
    pub async fn shutdown(&self) {
        let _ = self.tx.send(OpenClawBridgeMsg::Shutdown).await;
    }
}

// ---------------------------------------------------------------------------
// OpenClaw Channel Adapter
// ---------------------------------------------------------------------------

/// OpenClaw channel adapter configuration.
#[derive(Debug, Clone)]
pub struct OpenClawConfig {
    /// OpenClaw Gateway address (IP or hostname).
    pub gateway_host: String,
    /// OpenClaw Gateway WebSocket port.
    pub gateway_port: u16,
    /// Node display name shown in the OpenClaw dashboard.
    pub display_name: String,
    /// Node device ID (must be stable across reconnects).
    pub device_id: String,
    /// RSA public key for device authentication (Base64-encoded).
    pub public_key: Option<String>,
    /// RSA signature for challenge response (Base64-encoded).
    pub signature: Option<String>,
    /// Token for gateway authentication (if required).
    pub auth_token: Option<String>,
    /// Commands this node exposes (default: all common commands).
    pub commands: Vec<String>,
    /// Capabilities this node exposes.
    pub caps: Vec<String>,
}

impl Default for OpenClawConfig {
    fn default() -> Self {
        Self {
            gateway_host: "127.0.0.1".to_string(),
            gateway_port: DEFAULT_GATEWAY_PORT,
            display_name: "OpenFang Node".to_string(),
            device_id: uuid::Uuid::new_v4().to_string(),
            public_key: None,
            signature: None,
            auth_token: None,
            commands: vec![
                "screenshot".to_string(),
                "ui_tree".to_string(),
                "tap".to_string(),
                "swipe".to_string(),
                "type".to_string(),
                "press".to_string(),
                "launch".to_string(),
            ],
            caps: vec![
                "camera.snap".to_string(),
                "screenshot".to_string(),
                "ui_tree".to_string(),
                "tap".to_string(),
                "swipe".to_string(),
                "type".to_string(),
                "press".to_string(),
                "launch".to_string(),
            ],
        }
    }
}

/// OpenClaw channel adapter.
///
/// Implements the OpenClaw Gateway WebSocket node protocol v3, connecting as
/// a device node that receives command requests from the gateway and returns
/// results after processing via the OpenFang agent.
pub struct OpenClawAdapter {
    config: OpenClawConfig,
    /// Sender for sending invoke_result frames from the bridge to the WS task.
    bridge_handle: OpenClawBridgeHandle,
    /// Channel to signal the connection loop to stop.
    shutdown_tx: Arc<watch::Sender<bool>>,
    shutdown_rx: watch::Receiver<bool>,
}

impl OpenClawAdapter {
    pub fn new(config: OpenClawConfig) -> Self {
        let (tx, _rx) = mpsc::channel::<OpenClawBridgeMsg>(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config,
            bridge_handle: OpenClawBridgeHandle { tx },
            shutdown_tx: Arc::new(shutdown_tx),
            shutdown_rx,
        }
    }

    /// Returns a handle that the bridge can use to send `invoke_result` frames
    /// back to the OpenClaw Gateway over this adapter's WebSocket connection.
    pub fn bridge_handle(&self) -> OpenClawBridgeHandle {
        self.bridge_handle.clone()
    }

    fn gateway_url(&self) -> String {
        format!(
            "ws://{}:{}/gateway",
            self.config.gateway_host, self.config.gateway_port
        )
    }
}

#[async_trait]
impl ChannelAdapter for OpenClawAdapter {
    fn name(&self) -> &str {
        "openclaw"
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Custom("openclaw".to_string())
    }

    async fn start(
        self: Arc<Self>,
    ) -> Result<Pin<Box<dyn Stream<Item = ChannelMessage> + Send>>, Box<dyn std::error::Error>>
    {
        let (tx, rx) = mpsc::channel::<ChannelMessage>(64);
        let config = self.config.clone();
        let gateway_url = self.gateway_url();
        let shutdown_tx = self.shutdown_tx.clone();
        let shutdown_rx = self.shutdown_rx.clone();
        // Take the rx end of the bridge channel — the bridge_handle.tx feeds into it
        let bridge_rx = self.bridge_handle.tx.clone();

        tokio::spawn(async move {
            let mut backoff_secs: u64 = 1;
            let mut shutdown = shutdown_rx;

            loop {
                if *shutdown.borrow() {
                    info!("OpenClaw: shutdown requested, stopping connection loop");
                    break;
                }

                info!("OpenClaw: connecting to gateway at {gateway_url}");

                let ws_result = connect_async(&gateway_url).await;
                let (ws_stream, response) = match ws_result {
                    Ok((stream, resp)) => {
                        info!(
                            "OpenClaw: connected to gateway (status={})",
                            resp.status()
                        );
                        (stream, resp)
                    }
                    Err(e) => {
                        warn!(
                            "OpenClaw: connection failed: {e}, retrying in {backoff_secs}s"
                        );
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                        continue;
                    }
                };

                // Reset backoff on successful connection
                backoff_secs = 1;

                let (mut ws_tx, mut ws_rx) = ws_stream.split();
                let mut shutdown_inner = shutdown.clone();

                // --- Send connect request ---
                let connect_req = build_connect_request(&config);
                let req_json =
                    serde_json::to_string(&connect_req).expect("connect request always serializable");
                if let Err(e) = ws_tx.send(Message::Text(req_json.into())).await {
                    error!("OpenClaw: failed to send connect request: {e}");
                    continue;
                }

                // --- Handle messages until disconnect ---
                let should_reconnect = 'msg_loop: loop {
                    tokio::select! {
                        msg = ws_rx.next() => {
                            let msg = match msg {
                                Some(Ok(m)) => m,
                                Some(Err(e)) => {
                                    warn!("OpenClaw WebSocket error: {e}");
                                    break 'msg_loop true;
                                }
                                None => {
                                    info!("OpenClaw WebSocket closed by gateway");
                                    break 'msg_loop true;
                                }
                            };

                            let text = match msg {
                                Message::Text(t) => t.to_string(),
                                Message::Close(_) => {
                                    info!("OpenClaw: gateway sent close");
                                    break 'msg_loop false;
                                }
                                Message::Ping(data) => {
                                    let _ = ws_tx.send(Message::Pong(data)).await;
                                    continue;
                                }
                                _ => continue,
                            };

                            match parse_gateway_frame(&text) {
                                Some(Frame::HelloOk(_)) => {
                                    info!("OpenClaw: handshake complete, node registered");
                                    let tick_ack = serde_json::json!({
                                        "type": "event",
                                        "event": "node.pendingAck",
                                        "payload": {}
                                    });
                                    let _ = ws_tx
                                        .send(Message::Text(
                                            serde_json::to_string(&tick_ack).unwrap().into(),
                                        ))
                                        .await;
                                }
                                Some(Frame::Tick(_)) => {
                                    debug!("OpenClaw: received tick");
                                    let ack = serde_json::json!({
                                        "type": "event",
                                        "event": "node.pendingAck",
                                        "payload": {}
                                    });
                                    let _ = ws_tx
                                        .send(Message::Text(
                                            serde_json::to_string(&ack).unwrap().into(),
                                        ))
                                        .await;
                                }
                                Some(Frame::Shutdown(shutdown)) => {
                                    info!(
                                        "OpenClaw: gateway shutdown (reason={})",
                                        shutdown.reason
                                    );
                                    let restart_expected =
                                        shutdown.restart_expected_ms.is_some();
                                    if !restart_expected {
                                        break 'msg_loop false;
                                    }
                                    let wait_ms = shutdown.restart_expected_ms.unwrap_or(1000);
                                    tokio::time::sleep(Duration::from_millis(wait_ms)).await;
                                    break 'msg_loop true;
                                }
                                Some(Frame::NodeInvokeRequest(req)) => {
                                    debug!(
                                        "OpenClaw: invoke request id={} cmd={}",
                                        req.id, req.command
                                    );
                                    let channel_msg = ChannelMessage {
                                        channel: ChannelType::Custom("openclaw".to_string()),
                                        platform_message_id: req.id.clone(),
                                        sender: ChannelUser {
                                            platform_id: config.device_id.clone(),
                                            display_name: config.display_name.clone(),
                                            openfang_user: None,
                                        },
                                        content: ChannelContent::Text(format!(
                                            "/openclaw cmd={} params={}",
                                            req.command,
                                            serde_json::to_string(&req.params)
                                                .unwrap_or_default()
                                        )),
                                        target_agent: None,
                                        timestamp: Utc::now(),
                                        is_group: false,
                                        thread_id: None,
                                        metadata: {
                                            let mut m = HashMap::new();
                                            m.insert(
                                                "_openclaw_invoke_id".to_string(),
                                                serde_json::Value::String(req.id.clone()),
                                            );
                                            m.insert(
                                                "_openclaw_node_id".to_string(),
                                                serde_json::Value::String(req.node_id.clone()),
                                            );
                                            m.insert(
                                                "_openclaw_command".to_string(),
                                                serde_json::Value::String(req.command.clone()),
                                            );
                                            m.insert(
                                                "_openclaw_params".to_string(),
                                                serde_json::to_string(&req.params)
                                                    .map(serde_json::Value::String)
                                                    .unwrap_or(serde_json::Value::Null),
                                            );
                                            m.insert(
                                                "_openclaw_timeout_ms".to_string(),
                                                serde_json::Value::Number(
                                                    serde_json::Number::from(req.timeout_ms),
                                                ),
                                            );
                                            m
                                        },
                                    };

                                    if tx.send(channel_msg).await.is_err() {
                                        error!("OpenClaw: channel receiver dropped");
                                        break 'msg_loop false;
                                    }
                                }
                                Some(Frame::Unknown(unk)) => {
                                    debug!(
                                        "OpenClaw: unknown frame type: {}",
                                        unk.frame_type
                                    );
                                }
                                None => {
                                    debug!("OpenClaw: failed to parse frame: {text}");
                                }
                            }
                        }
                        // Handle bridge messages (invoke_result frames from dispatch)
                        bridge_msg = bridge_rx.recv() => {
                            match bridge_msg {
                                Some(OpenClawBridgeMsg::InvokeResult(frame)) => {
                                    let json = serde_json::to_string(&frame)
                                        .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string());
                                    if let Err(e) = ws_tx.send(Message::Text(json.into())).await {
                                        error!("OpenClaw: failed to send invoke_result: {e}");
                                    }
                                }
                                Some(OpenClawBridgeMsg::Shutdown) => {
                                    info!("OpenClaw: bridge shutdown signal received");
                                    let _ = ws_tx.close().await;
                                    return;
                                }
                                None => {
                                    debug!("OpenClaw: bridge handle channel closed");
                                }
                            }
                        }
                        _ = shutdown_inner.changed() => {
                            if *shutdown_inner.borrow() {
                                info!("OpenClaw: shutdown requested");
                                let _ = ws_tx.close().await;
                                return;
                            }
                        }
                    }
                };

                if !should_reconnect {
                    break;
                }

                warn!("OpenClaw: reconnecting in {backoff_secs}s");
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
            }

            info!("OpenClaw: connection loop stopped");
        });

        let _ = shutdown_tx;

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Box::pin(stream))
    }

    async fn send(
        &self,
        _user: &ChannelUser,
        _content: ChannelContent,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // OpenClaw responses are sent via OpenClawBridgeHandle, not this method.
        // The bridge detects openclaw invoke messages by metadata and calls
        // bridge_handle().send_invoke_result() directly.
        Ok(())
    }

    async fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.shutdown_tx.send(true);
        Ok(())
    }

    fn get_openclaw_bridge_handle(self: Arc<Self>) -> Option<Arc<dyn Any + Send + Sync>> {
        // Return the bridge handle wrapped in Arc<Any> so the bridge layer can
        // recover it via Arc::downcast::<OpenClawBridgeHandle>().
        Some(Arc::new(self.bridge_handle.clone()))
    }
}

// ---------------------------------------------------------------------------
// OpenClaw Protocol Frames
// ---------------------------------------------------------------------------

/// OpenClaw Gateway frame types.
#[derive(Debug)]
enum Frame {
    HelloOk(HelloOkPayload),
    Tick(TickPayload),
    Shutdown(ShutdownPayload),
    NodeInvokeRequest(NodeInvokeRequestPayload),
    Unknown(UnknownFrame),
}

#[derive(Debug, Deserialize)]
struct UnknownFrame {
    #[serde(alias = "type")]
    frame_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum HelloOkPayload {
    HelloOk {
        protocol: i64,
        server: ServerInfo,
        features: Features,
        snapshot: serde_json::Value,
        policy: Policy,
    },
}

#[derive(Debug, Deserialize)]
struct ServerInfo {
    version: String,
    #[serde(rename = "connId")]
    conn_id: String,
}

#[derive(Debug, Deserialize)]
struct Features {
    methods: Vec<String>,
    events: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Policy {
    #[serde(rename = "maxPayload")]
    max_payload: usize,
    #[serde(rename = "maxBufferedBytes")]
    max_buffered_bytes: usize,
    #[serde(rename = "tickIntervalMs")]
    tick_interval_ms: u64,
}

#[derive(Debug, Deserialize)]
struct TickPayload {
    ts: i64,
}

#[derive(Debug, Deserialize)]
struct ShutdownPayload {
    reason: String,
    #[serde(rename = "restartExpectedMs")]
    restart_expected_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct NodeInvokeRequestPayload {
    id: String,
    #[serde(rename = "nodeId")]
    node_id: String,
    command: String,
    params: serde_json::Value,
    #[serde(rename = "timeoutMs")]
    timeout_ms: u64,
    #[serde(rename = "idempotencyKey")]
    idempotency_key: Option<String>,
}

// ---------------------------------------------------------------------------
// Frame Building / Parsing
// ---------------------------------------------------------------------------

fn parse_gateway_frame(text: &str) -> Option<Frame> {
    let json: serde_json::Value = serde_json::from_str(text).ok()?;

    let frame_type = json.get("type")?.as_str()?;

    match frame_type {
        "res" => {
            let payload = json.get("payload")?;
            let payload_type = payload.get("type")?.as_str()?;
            match payload_type {
                "hello-ok" => {
                    let inner: HelloOkPayload =
                        serde_json::from_value(payload.clone()).ok()?;
                    Some(Frame::HelloOk(inner))
                }
                _ => Some(Frame::Unknown(UnknownFrame {
                    frame_type: format!("res/{payload_type}"),
                })),
            }
        }
        "event" => {
            let event = json.get("event")?.as_str()?;
            match event {
                "tick" => {
                    let payload = json.get("payload")?;
                    let tick: TickPayload = serde_json::from_value(payload.clone()).ok()?;
                    Some(Frame::Tick(tick))
                }
                "shutdown" => {
                    let payload = json.get("payload")?;
                    let shutdown: ShutdownPayload =
                        serde_json::from_value(payload.clone()).ok()?;
                    Some(Frame::Shutdown(shutdown))
                }
                "node.invoke_request" => {
                    let payload = json.get("payload")?;
                    let req: NodeInvokeRequestPayload =
                        serde_json::from_value(payload.clone()).ok()?;
                    Some(Frame::NodeInvokeRequest(req))
                }
                _ => Some(Frame::Unknown(UnknownFrame {
                    frame_type: format!("event/{event}"),
                })),
            }
        }
        _ => Some(Frame::Unknown(UnknownFrame {
            frame_type: frame_type.to_string(),
        })),
    }
}

fn build_connect_request(config: &OpenClawConfig) -> serde_json::Value {
    let mut client = serde_json::json!({
        "id": config.device_id,
        "displayName": config.display_name,
        "version": "1.0.0",
        "platform": "android",
        "deviceFamily": "Android",
        "mode": "node",
    });

    if let Some(ref pk) = config.public_key {
        client["publicKey"] = serde_json::json!(pk);
    }

    let mut params = serde_json::json!({
        "type": "req",
        "id": uuid::Uuid::new_v4().to_string(),
        "method": "connect",
        "params": {
            "minProtocol": OPENCLAW_PROTOCOL_VERSION,
            "maxProtocol": OPENCLAW_PROTOCOL_VERSION,
            "client": client,
            "role": "node",
            "commands": config.commands,
            "caps": config.caps,
            "locale": "en",
            "userAgent": format!("openfang/{}", env!("CARGO_PKG_VERSION")),
        }
    });

    if let (Some(ref pk), Some(ref sig)) = (&config.public_key, &config.signature) {
        params["params"]["device"] = serde_json::json!({
            "id": config.device_id,
            "publicKey": pk,
            "signature": sig,
            "signedAt": chrono::Utc::now().timestamp_millis(),
            "nonce": uuid::Uuid::new_v4().to_string(),
        });
    }

    if let Some(ref token) = config.auth_token {
        params["params"]["auth"] = serde_json::json!({ "token": token });
    }

    params
}

/// Build a node.invokeResult response frame.
pub fn build_invoke_result(
    invoke_id: &str,
    node_id: &str,
    ok: bool,
    payload: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "type": "req",
        "id": uuid::Uuid::new_v4().to_string(),
        "method": "node.invokeResult",
        "params": {
            "id": invoke_id,
            "nodeId": node_id,
            "ok": ok,
            "payload": payload,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_connect_request_default() {
        let config = OpenClawConfig::default();
        let req = build_connect_request(&config);
        assert_eq!(req["type"], "req");
        assert_eq!(req["method"], "connect");
        assert_eq!(req["params"]["minProtocol"], OPENCLAW_PROTOCOL_VERSION);
        assert_eq!(req["params"]["maxProtocol"], OPENCLAW_PROTOCOL_VERSION);
        assert_eq!(req["params"]["role"], "node");
        assert_eq!(req["params"]["client"]["mode"], "node");
    }

    #[test]
    fn test_build_invoke_result_success() {
        let result = build_invoke_result(
            "invoke-123",
            "device-abc",
            true,
            serde_json::json!({ "format": "png", "base64": "abc123" }),
        );
        assert_eq!(result["type"], "req");
        assert_eq!(result["method"], "node.invokeResult");
        assert_eq!(result["params"]["id"], "invoke-123");
        assert_eq!(result["params"]["nodeId"], "device-abc");
        assert!(result["params"]["ok"].as_bool().unwrap());
    }

    #[test]
    fn test_build_invoke_result_failure() {
        let result = build_invoke_result(
            "invoke-456",
            "device-xyz",
            false,
            serde_json::json!({ "error": "screen off" }),
        );
        assert!(!result["params"]["ok"].as_bool().unwrap());
    }

    #[test]
    fn test_parse_hello_ok_frame() {
        let text = serde_json::json!({
            "type": "res",
            "id": "req-1",
            "ok": true,
            "payload": {
                "type": "hello-ok",
                "protocol": 3,
                "server": { "version": "2026.1.0", "connId": "conn-abc" },
                "features": { "methods": ["node.invoke"], "events": ["node.invokeRequest"] },
                "snapshot": {},
                "policy": { "maxPayload": 10485760, "maxBufferedBytes": 5242880, "tickIntervalMs": 30000 }
            }
        })
        .to_string();

        let frame = parse_gateway_frame(&text);
        assert!(matches!(frame, Some(Frame::HelloOk(_))));
    }

    #[test]
    fn test_parse_tick_frame() {
        let text = serde_json::json!({
            "type": "event",
            "event": "tick",
            "payload": { "ts": 1712000000000 }
        })
        .to_string();

        let frame = parse_gateway_frame(&text);
        assert!(matches!(frame, Some(Frame::Tick(_))));
    }

    #[test]
    fn test_parse_node_invoke_request() {
        let text = serde_json::json!({
            "type": "event",
            "event": "node.invoke_request",
            "payload": {
                "id": "invoke-789",
                "nodeId": "device-abc",
                "command": "screenshot",
                "params": null,
                "timeoutMs": 30000,
                "idempotencyKey": "idem-1"
            }
        })
        .to_string();

        let frame = parse_gateway_frame(&text);
        match frame {
            Some(Frame::NodeInvokeRequest(req)) => {
                assert_eq!(req.id, "invoke-789");
                assert_eq!(req.command, "screenshot");
                assert_eq!(req.timeout_ms, 30000);
            }
            _ => panic!("expected NodeInvokeRequest frame"),
        }
    }

    #[test]
    fn test_parse_shutdown_frame() {
        let text = serde_json::json!({
            "type": "event",
            "event": "shutdown",
            "payload": {
                "reason": "restarting",
                "restartExpectedMs": 5000
            }
        })
        .to_string();

        let frame = parse_gateway_frame(&text);
        match frame {
            Some(Frame::Shutdown(s)) => {
                assert_eq!(s.reason, "restarting");
                assert_eq!(s.restart_expected_ms, Some(5000));
            }
            _ => panic!("expected Shutdown frame"),
        }
    }

    #[test]
    fn test_parse_unknown_frame() {
        let text = r#"{"type":"event","event":"unknown.event","payload":{}}"#;
        let frame = parse_gateway_frame(text);
        assert!(matches!(frame, Some(Frame::Unknown(_))));
    }

    #[test]
    fn test_parse_invalid_frame() {
        let frame = parse_gateway_frame("not json at all");
        assert!(frame.is_none());
    }

    #[test]
    fn test_openclaw_config_default() {
        let config = OpenClawConfig::default();
        assert_eq!(config.gateway_port, DEFAULT_GATEWAY_PORT);
        assert!(!config.commands.is_empty());
        assert!(config.commands.contains(&"screenshot".to_string()));
    }

    #[test]
    fn test_openclaw_bridge_handle_clone_and_send() {
        let (tx, mut rx) = mpsc::channel::<OpenClawBridgeMsg>(64);
        let handle = OpenClawBridgeHandle { tx };

        let handle2 = handle.clone();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let frame = build_invoke_result(
                    "invoke-abc",
                    "node-xyz",
                    true,
                    serde_json::json!({ "screenshot": "data" }),
                );
                handle2.send_invoke_result(frame).await;

                match rx.recv().await {
                    Some(OpenClawBridgeMsg::InvokeResult(frame)) => {
                        assert_eq!(frame["params"]["id"], "invoke-abc");
                        assert_eq!(frame["params"]["nodeId"], "node-xyz");
                        assert!(frame["params"]["ok"].as_bool().unwrap());
                    }
                    Some(OpenClawBridgeMsg::Shutdown) => panic!("unexpected shutdown"),
                    None => panic!("channel closed"),
                }
            });
    }

    #[test]
    fn test_openclaw_adapter_bridge_handle_access() {
        let config = OpenClawConfig::default();
        let adapter = OpenClawAdapter::new(config);
        let _handle = adapter.bridge_handle();
        // Verify handle can be cloned without issues
        let _clone = adapter.bridge_handle();
    }

    #[test]
    fn test_get_openclaw_bridge_handle() {
        use std::sync::Arc;
        use crate::types::ChannelAdapter;

        let adapter: Arc<OpenClawAdapter> = Arc::new(OpenClawAdapter::new(
            OpenClawConfig::default(),
        ));
        let handle_arc = adapter.get_openclaw_bridge_handle();
        assert!(handle_arc.is_some());

        let any = handle_arc.unwrap();
        // Downcast should work
        let _downcast: Arc<OpenClawBridgeHandle> =
            Arc::downcast(any).expect("should downcast to OpenClawBridgeHandle");
    }

    #[test]
    fn test_non_openclaw_adapter_returns_none() {
        // Verify the default implementation returns None by checking the trait default.
        // (This is implicit — we test it indirectly via the OpenClawAdapter override above.)
        // This test documents the expected behavior for non-OpenClaw adapters.
        let result = <dyn ChannelAdapter>::get_openclaw_bridge_handle(
            Arc::new(std::sync::Mutex::new(())) as Arc<dyn ChannelAdapter>
        );
        assert!(result.is_none());
    }
}
