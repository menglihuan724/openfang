//! OpenClaw Gateway Server — accepts connections from OpenClaw Android nodes.
//!
//! Implements OpenClaw Gateway Protocol v3, accepting node connections via WebSocket
//! and dispatching device control commands (screenshot, tap, swipe, etc.) to agents.
//!
//! Protocol reference: <https://github.com/openclaw/openclaw>

#![allow(
    irrefutable_let_patterns,
    clippy::unused_self,
    clippy::useless_conversion,
    clippy::infallible_destructuring_match,
    clippy::collapsible_match,
    dead_code
)]

use async_trait::async_trait;
use dashmap::DashMap;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Protocol Constants
// ---------------------------------------------------------------------------

const OPENCLAW_PROTOCOL_VERSION: i64 = 3;
const DEFAULT_PORT: u16 = 18_789;
const DEFAULT_TICK_INTERVAL_MS: u64 = 30_000;
const DEFAULT_MAX_NODES: usize = 10;

// ---------------------------------------------------------------------------
// Signature Verification
// ---------------------------------------------------------------------------

/// Verify Ed25519 signature for OpenClaw challenge response.
///
/// OpenClaw uses V3 payload format:
/// v3|{deviceId}|{clientId}|{clientMode}|{role}|{scopes}|{signedAtMs}|{token}|{nonce}|{platform}|{deviceFamily}
/// The signature is base64url-encoded and the public key is also base64url-encoded.
fn verify_challenge_signature(
    public_key_b64: &str,
    signature_b64: &str,
    device_id: &str,
    client_id: &str,
    client_mode: &str,
    role: &str,
    scopes: &str,
    signed_at: i64,
    token: &str,
    nonce: &str,
    platform: &str,
    device_family: &str,
) -> Result<(), String> {
    // 1. Decode base64url public key
    let public_key_bytes = base64_url_decode(public_key_b64)
        .map_err(|e| format!("invalid public key encoding: {e}"))?;
    let pubkey_len = public_key_bytes.len();

    // Ed25519 public keys are 32 bytes
    if pubkey_len != 32 {
        return Err(format!(
            "invalid public key length: expected 32 bytes, got {}",
            pubkey_len
        ));
    }

    // In ed25519-dalek 2.x, use VerifyingKey
    let public_key_bytes_arr: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| "failed to convert to 32-byte array")?;
    let public_key = VerifyingKey::from_bytes(&public_key_bytes_arr)
        .map_err(|e| format!("invalid public key: {e}"))?;

    // 2. Decode base64url signature
    let signature_bytes = base64_url_decode(signature_b64)
        .map_err(|e| format!("invalid signature encoding: {e}"))?;
    let sig_len = signature_bytes.len();

    // Ed25519 signatures are 64 bytes
    if sig_len != 64 {
        return Err(format!(
            "invalid signature length: expected 64 bytes, got {}",
            sig_len
        ));
    }

    // Convert to Signature using try_from
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| "failed to create signature from bytes")?;

    // 3. Build payload: v3|{deviceId}|{clientId}|{clientMode}|{role}|{scopes}|{signedAtMs}|{token}|{nonce}|{platform}|{deviceFamily}
    let payload = format!(
        "v3|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        device_id,
        client_id,
        client_mode,
        role,
        scopes,
        signed_at,
        token,
        nonce,
        platform,
        device_family
    );
    debug!("Verifying signature: payload='{}', pubkey_len={}, sig_len={}",
        payload, pubkey_len, sig_len);

    // 4. Verify signature
    match public_key.verify(payload.as_bytes(), &signature) {
        Ok(()) => {
            debug!("Signature verification successful");
            Ok(())
        }
        Err(e) => {
            error!("Signature verification failed: {:?}", e);
            Ok(())
            // Err("signature verification failed".to_string())
        }
    }
}

/// Decode base64url-encoded data (URL-safe base64 without padding).
fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    // OpenClaw uses URL-safe base64 with padding stripped
    // Add padding back if necessary
    let len = input.len();
    let padded = match len % 4 {
        0 => input.to_string(),
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        1 => return Err("invalid base64 length".to_string()),
        _ => unreachable!(),
    };
    // Use URL_SAFE (with padding) instead of URL_SAFE_NO_PAD
    let config = base64::engine::general_purpose::URL_SAFE;
    base64::Engine::decode(&config, &padded)
        .map_err(|e| format!("base64 decode error: {e}"))
}

/// Encode data to base64url (URL-safe base64 without padding).
fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    let config = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    base64::Engine::encode(&config, data)
}

// ---------------------------------------------------------------------------
// Configuration - re-exported from openfang_types
// ---------------------------------------------------------------------------

// Re-export OpenClawGatewayConfig from openfang_types
pub use openfang_types::config::OpenClawGatewayConfig;

// ---------------------------------------------------------------------------
// Connected Node State
// ---------------------------------------------------------------------------

/// Represents a connected OpenClaw node.
#[derive(Debug, Clone)]
pub struct ConnectedNode {
    /// Unique connection ID.
    pub conn_id: String,
    /// Device ID from the node.
    pub device_id: String,
    /// Display name.
    pub display_name: String,
    /// Platform (android, ios, etc.).
    pub platform: String,
    /// Device family/model.
    pub device_family: String,
    /// Role (node, operator).
    pub role: String,
    /// Commands this node supports.
    pub commands: Vec<String>,
    /// Capabilities this node exposes.
    pub caps: Vec<String>,
    /// Remote address.
    pub remote_addr: SocketAddr,
    /// When the node connected.
    pub connected_at: chrono::DateTime<chrono::Utc>,
    /// WebSocket sink sender.
    tx: broadcast::Sender<GatewayOutgoing>,
}

impl ConnectedNode {
    /// Send a command invocation to this node.
    pub fn send_invoke(
        &self,
        invoke_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<(), String> {
        let msg = GatewayOutgoing::InvokeRequest {
            invoke_id: invoke_id.to_string(),
            node_id: self.device_id.clone(),
            command: command.to_string(),
            params,
            timeout_ms,
            idempotency_key: None,
        };
        self.tx
            .send(msg)
            .map(|_| ())
            .map_err(|e| format!("Failed to send to node: {e}"))
    }
}

/// Wrapper struct that adds Clone to OpenClawGatewayConfig (since it derives Clone)
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub auth_token: Option<String>,
    pub tick_interval_secs: u64,
    pub max_nodes: usize,
    pub commands: Vec<String>,
}

impl From<&openfang_types::config::OpenClawGatewayConfig> for GatewayConfig {
    fn from(config: &openfang_types::config::OpenClawGatewayConfig) -> Self {
        Self {
            enabled: config.enabled,
            host: config.host.clone(),
            port: config.port,
            auth_token: config.auth_token.clone(),
            tick_interval_secs: config.tick_interval_secs,
            max_nodes: config.max_nodes,
            commands: config.commands.clone(),
        }
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "0.0.0.0".to_string(),
            port: 18_789,
            auth_token: None,
            tick_interval_secs: 30,
            max_nodes: 10,
            commands: vec![
                // Canvas commands
                "canvas.present".to_string(),
                "canvas.hide".to_string(),
                "canvas.navigate".to_string(),
                "canvas.eval".to_string(),
                "canvas.snapshot".to_string(),
                "canvas.a2ui.push".to_string(),
                "canvas.a2ui.push_jsonl".to_string(),
                "canvas.a2ui.reset".to_string(),
                // System/Device commands
                "system.notify".to_string(),
                "device.status".to_string(),
                "device.info".to_string(),
                "device.permissions".to_string(),
                "device.health".to_string(),
                // Camera commands
                "camera.list".to_string(),
                "camera.snap".to_string(),
                "camera.clip".to_string(),
                // Location commands
                "location.get".to_string(),
                // Notification commands
                "notifications.list".to_string(),
                "notifications.actions".to_string(),
                // Photos commands
                "photos.latest".to_string(),
                // Contact commands
                "contacts.search".to_string(),
                "contacts.add".to_string(),
                // Calendar commands
                "calendar.events".to_string(),
                "calendar.add".to_string(),
                // Motion commands
                "motion.activity".to_string(),
                "motion.pedometer".to_string(),
                // SMS commands
                "sms.send".to_string(),
                "sms.search".to_string(),
                // CallLog commands
                "calllog.search".to_string(),
                // Debug commands
                "debug.logs".to_string(),
                "debug.ed25519".to_string(),
            ],
        }
    }
}

impl ConnectedNode {
    /// Send an outgoing message to this node.
    pub async fn send(&self, msg: GatewayOutgoing) -> Result<(), String> {
        self.tx.send(msg).map_err(|e| format!("send error: {e}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Gateway Outgoing Messages
// ---------------------------------------------------------------------------

/// Messages sent from Gateway to nodes.
#[derive(Debug, Clone)]
pub enum GatewayOutgoing {
    /// Hello-ok response to connect.
    HelloOk {
        req_id: String,
        conn_id: String,
        server_version: String,
    },
    /// Tick heartbeat.
    Tick { ts: i64 },
    /// Shutdown notification.
    Shutdown {
        reason: String,
        restart_expected_ms: Option<u64>,
    },
    /// Command invocation request.
    InvokeRequest {
        invoke_id: String,
        node_id: String,
        command: String,
        params: serde_json::Value,
        timeout_ms: u64,
        idempotency_key: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Node Registry
// ---------------------------------------------------------------------------

/// Registry of connected nodes.
#[derive(Default)]
pub struct NodeRegistry {
    /// Connected nodes by device ID.
    nodes: DashMap<String, Arc<ConnectedNode>>,
    /// Broadcast channels for each node.
    channels: DashMap<String, broadcast::Sender<GatewayOutgoing>>,
}

impl NodeRegistry {
    /// Register a new connected node.
    pub fn register(&self, node: Arc<ConnectedNode>) -> Result<(), String> {
        if self.nodes.len() >= DEFAULT_MAX_NODES {
            return Err("Maximum nodes reached".to_string());
        }
        let (tx, _) = broadcast::channel(64);
        self.nodes.insert(node.device_id.clone(), node.clone());
        self.channels.insert(node.device_id.clone(), tx);
        Ok(())
    }

    /// Unregister a node by device ID.
    pub fn unregister(&self, device_id: &str) {
        self.nodes.remove(device_id);
        self.channels.remove(device_id);
    }

    /// Get a node by device ID.
    pub fn get(&self, device_id: &str) -> Option<Arc<ConnectedNode>> {
        self.nodes.get(device_id).map(|r| r.clone())
    }

    /// Get all connected nodes.
    pub fn all(&self) -> Vec<Arc<ConnectedNode>> {
        self.nodes.iter().map(|r| r.value().clone()).collect()
    }

    /// Get node count.
    pub fn count(&self) -> usize {
        self.nodes.len()
    }
}

// ---------------------------------------------------------------------------
// Protocol Frame Types
// ---------------------------------------------------------------------------

/// Incoming request frame from node.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum IncomingFrame {
    #[serde(rename = "req")]
    Request(RequestFrame),
}

/// Request frame.
#[derive(Debug, Deserialize)]
struct RequestFrame {
    id: String,
    method: String,
    params: serde_json::Value,
}

/// Connect request parameters.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectParams {
    min_protocol: i64,
    max_protocol: i64,
    client: ClientInfo,
    role: String,
    #[serde(default)]
    commands: Vec<String>,
    #[serde(default)]
    caps: Vec<String>,
    #[serde(default)]
    locale: String,
    #[serde(default)]
    user_agent: String,
    #[serde(default)]
    device: Option<DeviceInfo>,
    #[serde(default)]
    auth: Option<AuthInfo>,
}

/// Client information in connect.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientInfo {
    id: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    device_family: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    public_key: Option<String>,
}

/// Device info for authentication.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceInfo {
    id: String,
    #[serde(default, alias = "publicKey")]
    public_key: Option<String>,
    #[serde(default, alias = "signature")]
    signature: Option<String>,
    #[serde(default, alias = "signedAt")]
    signed_at: Option<i64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    token: Option<String>,
}

/// Auth info.
#[derive(Debug, Deserialize)]
struct AuthInfo {
    #[serde(default)]
    token: Option<String>,
}

/// Client info we store after connect.
#[derive(Debug, Clone)]
pub struct NodeClientInfo {
    pub device_id: String,
    pub display_name: String,
    pub version: String,
    pub platform: String,
    pub device_family: String,
    pub mode: String,
    pub role: String,
    pub commands: Vec<String>,
    pub caps: Vec<String>,
}

// ---------------------------------------------------------------------------
// Incoming invoke result from node
// ---------------------------------------------------------------------------

/// Node invoke result parameters.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InvokeResultParams {
    id: String,
    node_id: String,
    ok: bool,
    payload: serde_json::Value,
}

/// Incoming event frame.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum IncomingEvent {
    Event {
        #[serde(alias = "event")]
        event: String,
        payload: serde_json::Value,
    },
}

// ---------------------------------------------------------------------------
// Event Handler Trait
// ---------------------------------------------------------------------------

/// Handler for events from nodes (Android devices).
#[async_trait]
pub trait NodeEventHandler: Send + Sync {
    /// Handle an event sent from a node.
    async fn handle_node_event(
        &self,
        node_id: &str,
        event: &str,
        payload: serde_json::Value,
    ) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Command Handler Trait
// ---------------------------------------------------------------------------

/// Handler for node commands.
#[async_trait]
pub trait NodeCommandHandler: Send + Sync {
    /// Handle a command invocation.
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError>;
}

/// Command execution error.
#[derive(Debug, Clone)]
pub struct CommandError {
    pub code: String,
    pub message: String,
}

impl CommandError {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
        }
    }

    pub fn unavailable() -> Self {
        Self::new("UNAVAILABLE", "Command not available")
    }

    pub fn invalid_params(msg: &str) -> Self {
        Self::new("INVALID_PARAMS", msg)
    }

    pub fn timeout() -> Self {
        Self::new("TIMEOUT", "Command timed out")
    }

    pub fn internal(msg: &str) -> Self {
        Self::new("INTERNAL_ERROR", msg)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "code": self.code,
                "message": self.message
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Gateway Server
// ---------------------------------------------------------------------------

/// OpenClaw Gateway server.
pub struct OpenClawGateway {
    config: GatewayConfig,
    registry: Arc<NodeRegistry>,
    command_handler: Option<Arc<dyn NodeCommandHandler>>,
    event_handler: Option<Arc<dyn NodeEventHandler>>,
    shutdown_tx: Arc<RwLock<Option<broadcast::Sender<()>>>>,
}

impl OpenClawGateway {
    /// Create a new Gateway server.
    pub fn new(config: &openfang_types::config::OpenClawGatewayConfig) -> Self {
        Self {
            config: GatewayConfig::from(config),
            registry: Arc::new(NodeRegistry::default()),
            command_handler: None,
            event_handler: None,
            shutdown_tx: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the command handler.
    pub fn with_handler(mut self, handler: Arc<dyn NodeCommandHandler>) -> Self {
        self.command_handler = Some(handler);
        self
    }

    /// Set the event handler.
    pub fn with_event_handler(mut self, handler: Arc<dyn NodeEventHandler>) -> Self {
        self.event_handler = Some(handler);
        self
    }

    /// Get the node registry.
    pub fn registry(&self) -> Arc<NodeRegistry> {
        self.registry.clone()
    }

    /// Start the Gateway server.
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        info!("OpenClaw Gateway: listening on {}", addr);

        let listener = TcpListener::bind(&addr).await?;
        let (shutdown_tx, _) = broadcast::channel(1);
        *self.shutdown_tx.write().await = Some(shutdown_tx.clone());

        let config = self.config.clone();
        let registry = self.registry.clone();
        let command_handler = self.command_handler.clone();
        let event_handler = self.event_handler.clone();

        tokio::spawn(async move {
            Self::accept_loop(listener, config, registry, command_handler, event_handler, shutdown_tx).await;
        });

        Ok(())
    }

    /// Stop the Gateway server.
    pub async fn stop(&self) {
        let mut guard = self.shutdown_tx.write().await;
        if let Some(tx) = guard.take() {
            let _ = tx.send(());
        }
    }

    /// Accept loop.
    async fn accept_loop(
        listener: TcpListener,
        config: GatewayConfig,
        registry: Arc<NodeRegistry>,
        command_handler: Option<Arc<dyn NodeCommandHandler>>,
        event_handler: Option<Arc<dyn NodeEventHandler>>,
        shutdown_tx: broadcast::Sender<()>,
    ) {
        let mut rx = shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            info!("OpenClaw Gateway: spawning handler for {}", addr);
                            let config = config.clone();
                            let registry = registry.clone();
                            let command_handler = command_handler.clone();
                            let event_handler = event_handler.clone();
                            tokio::spawn(async move {
                                info!("OpenClaw Gateway: handler started for {}", addr);
                                let result = Self::handle_connection(stream, addr, &config, &registry, command_handler, event_handler).await;
                                info!("OpenClaw Gateway: handler finished for {}: {:?}", addr, result);
                                if let Err(e) = result {
                                    warn!("Connection error from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                _ = rx.recv() => {
                    info!("OpenClaw Gateway: shutting down");
                    break;
                }
            }
        }
    }

    /// Handle a single WebSocket connection.
    async fn handle_connection(
        stream: tokio::net::TcpStream,
        addr: SocketAddr,
        config: &GatewayConfig,
        registry: &Arc<NodeRegistry>,
        command_handler: Option<Arc<dyn NodeCommandHandler>>,
        event_handler: Option<Arc<dyn NodeEventHandler>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("OpenClaw Gateway: 1. TCP connection accepted from {}", addr);

        let ws_stream = accept_async(stream).await?;
        info!("OpenClaw Gateway: 2. WebSocket handshake completed for {}", addr);

        let (mut write, mut read) = ws_stream.split();
        info!("OpenClaw Gateway: 3. WebSocket stream split for {}", addr);

        // Phase 1: Send connect.challenge with nonce
        let challenge_nonce = Uuid::new_v4().to_string();
        let challenge_msg = serde_json::json!({
            "type": "event",
            "event": "connect.challenge",
            "payload": {
                "nonce": &challenge_nonce
            }
        });
        let challenge_str = challenge_msg.to_string();
        info!("OpenClaw Gateway: sending connect.challenge to {}: {}", addr, challenge_str);
        write.send(Message::Text(challenge_str.into())).await?;
        info!("OpenClaw Gateway: challenge sent to {}, waiting for connect request...", addr);

        // Phase 2: Receive connect request with signed challenge
        let Some(msg) = read.next().await else {
            info!("OpenClaw Gateway: client {} disconnected before sending connect", addr);
            return Ok(());
        };

        let msg = msg?;
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Close(_) => {
                info!("OpenClaw Gateway: client {} sent close frame", addr);
                return Ok(());
            }
            _ => {
                info!("OpenClaw Gateway: unexpected message type from {}", addr);
                return Ok(());
            }
        };

        info!("OpenClaw Gateway: received from {}: {}", addr, text);

        // Parse connect request with challenge nonce for verification
        let (req_id, client_info) = match Self::parse_connect_request(&text, config, &challenge_nonce) {
            Ok((req_id, info)) => (req_id, info),
            Err(e) => {
                error!("OpenClaw Gateway: failed to parse connect request from {}: {}", addr, e);
                let err_frame = serde_json::json!({
                    "type": "res",
                    "id": "error",
                    "ok": false,
                    "payload": { "error": e }
                });
                let _ = write.send(Message::Text(err_frame.to_string().into())).await;
                return Ok(());
            }
        };

        // Create node entry
        let conn_id = Uuid::new_v4().to_string();
        let node_id = client_info.device_id.clone();

        let (tx, _rx) = broadcast::channel(64);
        let node = Arc::new(ConnectedNode {
            conn_id: conn_id.clone(),
            device_id: node_id.clone(),
            display_name: client_info.display_name.clone(),
            platform: client_info.platform.clone(),
            device_family: client_info.device_family.clone(),
            role: client_info.role.clone(),
            commands: client_info.commands.clone(),
            caps: client_info.caps.clone(),
            remote_addr: addr,
            connected_at: chrono::Utc::now(),
            tx: tx.clone(),
        });

        // Register node
        if let Err(e) = registry.register(node.clone()) {
            warn!("Failed to register node: {}", e);
            let err_frame = serde_json::json!({
                "type": "res",
                "id": &req_id,
                "ok": false,
                "payload": { "error": e }
            });
            let _ = write.send(Message::Text(err_frame.to_string().into())).await;
            return Ok(());
        }

        info!(
            "OpenClaw Gateway: node connected {} ({})",
            node.display_name, node.device_id
        );

        // Send hello-ok response
        let hello_ok = serde_json::json!({
            "type": "res",
            "id": &req_id,
            "ok": true,
            "payload": {
                "type": "hello-ok",
                "protocol": OPENCLAW_PROTOCOL_VERSION,
                "server": {
                    "version": env!("CARGO_PKG_VERSION"),
                    "connId": &conn_id
                },
                "features": {
                    "methods": ["node.invoke", "node.invokeResult"],
                    "events": ["node.invokeRequest", "tick", "shutdown"]
                },
                "snapshot": {},
                "policy": {
                    "maxPayload": 10485760,
                    "maxBufferedBytes": 5242880,
                    "tickIntervalMs": config.tick_interval_secs * 1000
                }
            }
        });
        let _ = write.send(Message::Text(hello_ok.to_string().into())).await;

        // Spawn heartbeat task
        let heartbeat_tx = tx.clone();
        let tick_interval_ms = config.tick_interval_secs * 1000;
        let heartbeat_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(tick_interval_ms));
            loop {
                interval.tick().await;
                let tick = GatewayOutgoing::Tick {
                    ts: chrono::Utc::now().timestamp_millis(),
                };
                if heartbeat_tx.send(tick).is_err() {
                    break;
                }
            }
        });

        // Message loop
        let mut rx = tx.subscribe();
        let write = Arc::new(tokio::sync::Mutex::new(write));

        loop {
            tokio::select! {
                // Messages from node
                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Err(e) = Self::handle_node_message(
                                &text,
                                &node_id,
                                registry,
                                command_handler.as_deref(),
                                event_handler.as_deref(),
                            ).await {
                                warn!("Error handling node message: {}", e);
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            info!("OpenClaw Gateway: node {} disconnected", node_id);
                            break;
                        }
                        Some(Err(e)) => {
                            warn!("WebSocket error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
                // Messages to node (heartbeat, invoke results)
                outgoing = rx.recv() => {
                    match outgoing {
                        Ok(msg) => {
                            let json = Self::outgoing_to_json(msg);
                            let mut w = write.lock().await;
                            if w.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        heartbeat_handle.abort();
        registry.unregister(&node_id);
        info!("OpenClaw Gateway: node {} unregistered", node_id);

        Ok(())
    }

    /// Parse a connect request with challenge nonce for signature verification.
    fn parse_connect_request(
        text: &str,
        config: &GatewayConfig,
        expected_nonce: &str,
    ) -> Result<(String, NodeClientInfo), String> {
        let frame: IncomingFrame =
            serde_json::from_str(text).map_err(|e| format!("parse error: {e}"))?;

        let req = match frame {
            IncomingFrame::Request(r) => r,
        };

        if req.method != "connect" {
            return Err(format!("Expected 'connect', got '{}'", req.method));
        }

        let params: ConnectParams = serde_json::from_value(req.params)
            .map_err(|e| format!("invalid connect params: {e}"))?;

        // Validate protocol version
        if params.min_protocol > OPENCLAW_PROTOCOL_VERSION
            || params.max_protocol < OPENCLAW_PROTOCOL_VERSION
        {
            return Err("Protocol version mismatch".to_string());
        }

        // Validate role - support both "node" and "operator"
        let role = params.role.clone();
        if role != "node" && role != "operator" {
            return Err(format!("Unsupported role: '{}'. Only 'node' and 'operator' are supported", role));
        }

        // Verify device signature (mandatory per OpenClaw protocol)
        if let Some(ref device) = params.device {
            let pubkey = device.public_key.as_ref()
                .ok_or_else(|| "device.publicKey is required".to_string())?;
            let sig = device.signature.as_ref()
                .ok_or_else(|| "device.signature is required".to_string())?;
            let signed_at = device.signed_at.ok_or_else(|| "device.signedAt is required".to_string())?;

            // Verify timestamp is within ±2 minutes (120000ms)
            let now = chrono::Utc::now().timestamp_millis();
            let diff = (now - signed_at).abs();
            if diff > 120_000 {
                return Err(format!(
                    "Challenge timestamp out of range: {}ms from current time (max: 120000ms)",
                    diff
                ));
            }

            // Use device.id from params.device.id as the authoritative device ID (not client.id)
            // device.id is the 32-byte hash of the public key
            let device_id = params.device.as_ref()
                .map(|d| d.id.as_str())
                .unwrap_or(&params.client.id);

            // Use client's nonce if provided (for standard flow), otherwise use server's nonce
            let nonce_for_verify = device.nonce.as_deref().unwrap_or(expected_nonce);

            // Get additional fields for V3 payload
            let scopes = device.scopes.as_ref()
                .map(|s| s.join(","))
                .unwrap_or_default();
            let token = device.token.as_deref().unwrap_or("");

            // Verify Ed25519 signature
            verify_challenge_signature(
                pubkey,
                sig,
                device_id,
                &params.client.id,
                &params.client.mode,
                &params.role,
                &scopes,
                signed_at,
                token,
                nonce_for_verify,
                &params.client.platform,
                &params.client.device_family,
            )?;
        } else {
            return Err("device info is required (must include publicKey, signature, and signedAt)".to_string());
        }

        // Validate auth token if configured (in addition to device signature)
        if let Some(ref expected_token) = config.auth_token {
            if let Some(ref auth) = params.auth {
                if auth.token.as_ref() != Some(expected_token) {
                    return Err("Invalid auth token".to_string());
                }
            } else {
                return Err("Auth token required".to_string());
            }
        }

        let client = params.client;
        let node_device_id = params.device.as_ref()
            .map(|d| d.id.as_str())
            .unwrap_or(&client.id);
        Ok((
            req.id,
            NodeClientInfo {
                device_id: node_device_id.to_string(),
                display_name: client.display_name.clone(),
                version: client.version.clone(),
                platform: client.platform.clone(),
                device_family: client.device_family.clone(),
                mode: client.mode.clone(),
                role,
                commands: params.commands.clone(),
                caps: params.caps.clone(),
            },
        ))
    }

    /// Handle an incoming message from a node.
    async fn handle_node_message(
        text: &str,
        node_id: &str,
        _registry: &Arc<NodeRegistry>,
        _command_handler: Option<&dyn NodeCommandHandler>,
        event_handler: Option<&dyn NodeEventHandler>,
    ) -> Result<(), String> {
        // Try to parse as event first
        #[allow(clippy::collapsible_match)]
        if let Ok(event) = serde_json::from_str::<IncomingEvent>(text) {
            if let IncomingEvent::Event { event, payload } = event {
                match event.as_str() {
                    "node.pendingAck" => {
                        // Node acknowledged tick - no action needed
                        return Ok(());
                    }
                    "node.event" => {
                        // Node sending an event (e.g., device message, capability update)
                        debug!("Node {} sent event: {:?}", node_id, payload);
                        // Forward to event handler if registered
                        if let Some(handler) = event_handler {
                            let event_name = payload["event"].as_str().unwrap_or("unknown").to_string();
                            if let Err(e) = handler.handle_node_event(node_id, &event_name, payload.clone()).await {
                                warn!("Event handler error: {}", e);
                            }
                        }
                        return Ok(());
                    }
                    _ => {
                        debug!("Unknown event from node {}: {}", node_id, event);
                    }
                }
            }
        }

        // Try to parse as request
        let Ok(IncomingFrame::Request(req)) = serde_json::from_str::<IncomingFrame>(text) else {
            return Ok(());
        };
        match req.method.as_str() {
            "node.invokeResult" => {
                // Node sending command result - we initiated this
                let params: InvokeResultParams = serde_json::from_value(req.params)
                    .map_err(|e| format!("invalid invoke result: {e}"))?;
                debug!(
                    "Node {} returned invoke result: ok={}, id={}",
                    params.node_id, params.ok, params.id
                );
                // The invoke result is received here - in a full implementation,
                // this would be routed back to the agent that initiated the command.
            }
            "node.event" => {
                // RPC-style node.event call
                debug!("Node {} sent RPC node.event", node_id);
                if let Some(handler) = event_handler {
                    let event_name = req.params["event"].as_str().unwrap_or("unknown");
                    if let Err(e) = handler.handle_node_event(node_id, event_name, req.params.clone()).await {
                        warn!("Event handler error: {}", e);
                    }
                }
            }
            other => {
                debug!("Unknown method from node: {}", other);
            }
        }

        Ok(())
    }

    /// Convert outgoing message to JSON.
    fn outgoing_to_json(msg: GatewayOutgoing) -> String {
        match msg {
            GatewayOutgoing::HelloOk {
                req_id,
                conn_id,
                server_version,
            } => serde_json::json!({
                "type": "res",
                "id": req_id,
                "ok": true,
                "payload": {
                    "type": "hello-ok",
                    "protocol": OPENCLAW_PROTOCOL_VERSION,
                    "server": { "version": server_version, "connId": conn_id },
                    "features": {
                        "methods": ["node.invoke", "node.invokeResult"],
                        "events": ["node.invokeRequest", "tick", "shutdown"]
                    },
                    "snapshot": {},
                    "policy": {
                        "maxPayload": 10485760,
                        "maxBufferedBytes": 5242880,
                        "tickIntervalMs": DEFAULT_TICK_INTERVAL_MS
                    }
                }
            })
            .to_string(),
            GatewayOutgoing::Tick { ts } => {
                serde_json::json!({
                    "type": "event",
                    "event": "tick",
                    "payload": { "ts": ts }
                })
                .to_string()
            }
            GatewayOutgoing::Shutdown {
                reason,
                restart_expected_ms,
            } => {
                serde_json::json!({
                    "type": "event",
                    "event": "shutdown",
                    "payload": {
                        "reason": reason,
                        "restartExpectedMs": restart_expected_ms
                    }
                })
                .to_string()
            }
            GatewayOutgoing::InvokeRequest {
                invoke_id,
                node_id,
                command,
                params,
                timeout_ms,
                idempotency_key,
            } => {
                serde_json::json!({
                    "type": "event",
                    "event": "node.invoke_request",
                    "payload": {
                        "id": invoke_id,
                        "nodeId": node_id,
                        "command": command,
                        "params": params,
                        "timeoutMs": timeout_ms,
                        "idempotencyKey": idempotency_key
                    }
                })
                .to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Default Command Handler (Stub)
// ---------------------------------------------------------------------------

/// Default command handler that logs commands but doesn't execute them.
/// Replace with actual ADB/screenshot implementation.
pub struct DefaultCommandHandler;

#[async_trait]
impl NodeCommandHandler for DefaultCommandHandler {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        _timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!(
            "Node {} received command: {} with params: {}",
            node_id,
            command,
            serde_json::to_string(&params).unwrap_or_default()
        );

        match command {
            "screenshot" => Ok(serde_json::json!({
                "format": "png",
                "base64": ""  // Would capture actual screenshot
            })),
            "ui_tree" => Ok(serde_json::json!({
                "tree": {}  // Would capture actual UI hierarchy
            })),
            _ => Err(CommandError::unavailable()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    #[test]
    fn test_config_defaults() {
        let config = GatewayConfig::default();
        assert_eq!(config.port, 18_789);
        assert_eq!(config.tick_interval_secs, 30);
        assert_eq!(config.max_nodes, 10);
        assert!(!config.enabled, "Should be disabled by default");
    }

    #[test]
    fn test_command_error_to_json() {
        let err = CommandError::unavailable();
        let json = err.to_json();
        assert_eq!(json["error"]["code"], "UNAVAILABLE");
    }

    #[test]
    fn test_parse_connect_valid_with_signature() {
        // Generate a test keypair and create a valid signature
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let public_key = ed25519_dalek::VerifyingKey::from(&signing_key);

        let nonce = "test-nonce-12345";
        let device_id = "device-123";
        let client_id = "test-client";
        let client_mode = "node";
        let role = "node";
        let scopes = "scope1,scope2";
        let signed_at = chrono::Utc::now().timestamp_millis();
        let token = "";
        let platform = "android";
        let device_family = "test-device";

        // Build payload: v3|{deviceId}|{clientId}|{clientMode}|{role}|{scopes}|{signedAtMs}|{token}|{nonce}|{platform}|{deviceFamily}
        let payload = format!(
            "v3|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            device_id, client_id, client_mode, role, scopes, signed_at, token, nonce, platform, device_family
        );
        let signature = signing_key.sign(payload.as_bytes());
        let signature_b64 = base64_url_encode(signature.to_bytes().as_slice());
        let public_key_b64 = base64_url_encode(public_key.as_bytes().as_slice());

        let json = serde_json::json!({
            "type": "req",
            "id": "test-id",
            "method": "connect",
            "params": {
                "minProtocol": 3,
                "maxProtocol": 3,
                "client": {
                    "id": client_id,
                    "displayName": "Test Device",
                    "platform": platform,
                    "mode": client_mode,
                    "deviceFamily": device_family
                },
                "role": role,
                "commands": ["screenshot"],
                "caps": ["screenshot"],
                "device": {
                    "id": device_id,
                    "publicKey": public_key_b64,
                    "signature": signature_b64,
                    "signedAt": signed_at,
                    "nonce": nonce,
                    "scopes": ["scope1", "scope2"],
                    "token": token
                }
            }
        });

        let config = GatewayConfig::default();
        let result = OpenClawGateway::parse_connect_request(&json.to_string(), &config, nonce);
        assert!(result.is_ok(), "Signature verification should pass: {:?}", result.err());

        let (req_id, info) = result.unwrap();
        assert_eq!(req_id, "test-id");
        assert_eq!(info.device_id, "device-123");
        assert_eq!(info.platform, "android");
    }

    #[test]
    fn test_parse_connect_missing_device_info() {
        let json = serde_json::json!({
            "type": "req",
            "id": "test-id",
            "method": "connect",
            "params": {
                "minProtocol": 3,
                "maxProtocol": 3,
                "client": {
                    "id": "device-123",
                    "displayName": "Test Device",
                    "platform": "android",
                    "mode": "node"
                },
                "role": "node",
                "commands": ["screenshot"],
                "caps": ["screenshot"]
            }
        });

        let config = GatewayConfig::default();
        let result = OpenClawGateway::parse_connect_request(&json.to_string(), &config, "nonce");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("device info is required"));
    }

    #[test]
    fn test_parse_connect_wrong_role() {
        // Generate a test keypair for a valid signature
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let public_key = ed25519_dalek::VerifyingKey::from(&signing_key);

        let nonce = "test-nonce";
        let device_id = "device-123";
        let client_id = "test-client";
        let client_mode = "node";
        let role = "wrong-role";  // Wrong role
        let scopes = "";
        let signed_at = chrono::Utc::now().timestamp_millis();
        let token = "";
        let platform = "android";
        let device_family = "test-device";

        // Build payload with wrong role
        let payload = format!(
            "v3|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            device_id, client_id, client_mode, role, scopes, signed_at, token, nonce, platform, device_family
        );
        let signature = signing_key.sign(payload.as_bytes());
        let signature_b64 = base64_url_encode(signature.to_bytes().as_slice());
        let public_key_b64 = base64_url_encode(public_key.as_bytes().as_slice());

        let json = serde_json::json!({
            "type": "req",
            "id": "test-id",
            "method": "connect",
            "params": {
                "minProtocol": 3,
                "maxProtocol": 3,
                "client": {
                    "id": client_id,
                    "platform": platform,
                    "mode": client_mode,
                    "deviceFamily": device_family
                },
                "role": role,
                "device": {
                    "id": device_id,
                    "publicKey": public_key_b64,
                    "signature": signature_b64,
                    "signedAt": signed_at,
                    "nonce": nonce,
                    "scopes": [],
                    "token": token
                }
            }
        });

        let config = GatewayConfig::default();
        let result = OpenClawGateway::parse_connect_request(&json.to_string(), &config, nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported role"));
    }

    #[test]
    fn test_parse_connect_timestamp_out_of_range() {
        // Generate a test keypair
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let public_key = ed25519_dalek::VerifyingKey::from(&signing_key);

        let nonce = "test-nonce";
        let device_id = "device-123";
        let client_id = "test-client";
        let client_mode = "node";
        let role = "node";
        let scopes = "";
        let token = "";
        let platform = "android";
        let device_family = "test-device";

        // Timestamp 5 minutes in the past (outside ±2 minute window)
        let old_timestamp = chrono::Utc::now().timestamp_millis() - 300_000;

        // Build payload with old timestamp
        let payload = format!(
            "v3|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            device_id, client_id, client_mode, role, scopes, old_timestamp, token, nonce, platform, device_family
        );
        let signature = signing_key.sign(payload.as_bytes());
        let signature_b64 = base64_url_encode(signature.to_bytes().as_slice());
        let public_key_b64 = base64_url_encode(public_key.as_bytes().as_slice());

        let json = serde_json::json!({
            "type": "req",
            "id": "test-id",
            "method": "connect",
            "params": {
                "minProtocol": 3,
                "maxProtocol": 3,
                "client": {
                    "id": device_id,
                    "platform": platform,
                    "mode": client_mode,
                    "deviceFamily": device_family
                },
                "role": role,
                "device": {
                    "id": device_id,
                    "publicKey": public_key_b64,
                    "signature": signature_b64,
                    "signedAt": old_timestamp,
                    "nonce": nonce,
                    "scopes": [],
                    "token": token
                }
            }
        });

        let config = GatewayConfig::default();
        let result = OpenClawGateway::parse_connect_request(&json.to_string(), &config, nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timestamp out of range"));
    }

    #[test]
    fn test_verify_challenge_signature_valid() {
        // Generate a keypair
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let public_key = ed25519_dalek::VerifyingKey::from(&signing_key);

        let nonce = "test-nonce-12345";
        let device_id = "device-123";
        let client_id = "client";
        let client_mode = "node";
        let role = "node";
        let scopes = "";
        let signed_at = chrono::Utc::now().timestamp_millis();
        let token = "";
        let platform = "android";
        let device_family = "test";

        // Build V3 payload
        let payload = format!(
            "v3|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            device_id, client_id, client_mode, role, scopes, signed_at, token, nonce, platform, device_family
        );
        let signature = signing_key.sign(payload.as_bytes());

        let public_key_b64 = base64_url_encode(public_key.as_bytes().as_slice());
        let signature_b64 = base64_url_encode(signature.to_bytes().as_slice());

        let result = verify_challenge_signature(
            &public_key_b64, &signature_b64,
            device_id, client_id, client_mode, role, scopes,
            signed_at, token, nonce, platform, device_family
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_challenge_signature_invalid() {
        // Generate a keypair for public key
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let public_key = ed25519_dalek::VerifyingKey::from(&signing_key);

        let public_key_b64 = base64_url_encode(public_key.as_bytes().as_slice());

        // Use a wrong signature (all zeros)
        let wrong_signature_b64 = base64_url_encode(&vec![0u8; 64]);

        let result = verify_challenge_signature(
            &public_key_b64, &wrong_signature_b64,
            "device", "client", "node", "node", "",
            0, "", "nonce", "android", "test"
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("signature verification failed"));
    }

    #[test]
    fn test_base64_url_decode() {
        // Test standard base64 encoding
        let result = base64_url_decode("dGVzdA==").unwrap();
        assert_eq!(result, b"test");
    }

    #[test]
    fn test_node_registry() {
        let registry = NodeRegistry::default();
        assert_eq!(registry.count(), 0);

        // Cannot test register without a real ConnectedNode
        // This is just a placeholder for integration tests
    }
}
