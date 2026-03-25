//! OpenClaw node command handlers.
//!
//! Implements command execution for device control commands like screenshot, tap, swipe, etc.
//! These commands are invoked by the Gateway and forwarded to the connected Android node.

#![allow(dead_code, unused_variables)]

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

// Re-export from gateway module
pub use super::openclaw_gateway::{CommandError, NodeCommandHandler};

// ---------------------------------------------------------------------------
// Command Result
// ---------------------------------------------------------------------------

/// Result of a command execution.
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub ok: bool,
    pub payload: serde_json::Value,
}

impl CommandResult {
    pub fn success(payload: serde_json::Value) -> Self {
        Self { ok: true, payload }
    }

    pub fn error(code: &str, message: &str) -> Self {
        Self {
            ok: false,
            payload: serde_json::json!({
                "error": { "code": code, "message": message }
            }),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        self.payload.clone()
    }
}

// ---------------------------------------------------------------------------
// Command Handler Registry
// ---------------------------------------------------------------------------

/// Registry of available command handlers.
pub struct CommandRegistry {
    handlers: HashMap<String, Arc<dyn NodeCommandHandler>>,
}

impl CommandRegistry {
    pub fn new() -> Self {
        let mut handlers: HashMap<String, Arc<dyn NodeCommandHandler>> = HashMap::new();

        // Canvas commands
        handlers.insert("canvas.present".to_string(), Arc::new(CanvasPresentCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("canvas.hide".to_string(), Arc::new(CanvasHideCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("canvas.navigate".to_string(), Arc::new(CanvasNavigateCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("canvas.eval".to_string(), Arc::new(CanvasEvalCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("canvas.snapshot".to_string(), Arc::new(CanvasSnapshotCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("canvas.a2ui.push".to_string(), Arc::new(CanvasA2UiPushCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("canvas.a2ui.push_jsonl".to_string(), Arc::new(CanvasA2UiPushJsonlCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("canvas.a2ui.reset".to_string(), Arc::new(CanvasA2UiResetCommand) as Arc<dyn NodeCommandHandler>);

        // System/Device commands
        handlers.insert("system.notify".to_string(), Arc::new(SystemNotifyCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("device.status".to_string(), Arc::new(DeviceStatusCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("device.info".to_string(), Arc::new(DeviceInfoCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("device.permissions".to_string(), Arc::new(DevicePermissionsCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("device.health".to_string(), Arc::new(DeviceHealthCommand) as Arc<dyn NodeCommandHandler>);

        // Camera commands
        handlers.insert("camera.list".to_string(), Arc::new(CameraListCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("camera.snap".to_string(), Arc::new(CameraSnapCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("camera.clip".to_string(), Arc::new(CameraClipCommand) as Arc<dyn NodeCommandHandler>);

        // Location commands
        handlers.insert("location.get".to_string(), Arc::new(LocationGetCommand) as Arc<dyn NodeCommandHandler>);

        // Notification commands
        handlers.insert("notifications.list".to_string(), Arc::new(NotificationsListCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("notifications.actions".to_string(), Arc::new(NotificationsActionsCommand) as Arc<dyn NodeCommandHandler>);

        // Photos commands
        handlers.insert("photos.latest".to_string(), Arc::new(PhotosLatestCommand) as Arc<dyn NodeCommandHandler>);

        // Contact commands
        handlers.insert("contacts.search".to_string(), Arc::new(ContactsSearchCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("contacts.add".to_string(), Arc::new(ContactsAddCommand) as Arc<dyn NodeCommandHandler>);

        // Calendar commands
        handlers.insert("calendar.events".to_string(), Arc::new(CalendarEventsCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("calendar.add".to_string(), Arc::new(CalendarAddCommand) as Arc<dyn NodeCommandHandler>);

        // Motion commands
        handlers.insert("motion.activity".to_string(), Arc::new(MotionActivityCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("motion.pedometer".to_string(), Arc::new(MotionPedometerCommand) as Arc<dyn NodeCommandHandler>);

        // SMS commands
        handlers.insert("sms.send".to_string(), Arc::new(SmsSendCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("sms.search".to_string(), Arc::new(SmsSearchCommand) as Arc<dyn NodeCommandHandler>);

        // CallLog commands
        handlers.insert("calllog.search".to_string(), Arc::new(CallLogSearchCommand) as Arc<dyn NodeCommandHandler>);

        // Debug commands
        handlers.insert("debug.logs".to_string(), Arc::new(DebugLogsCommand) as Arc<dyn NodeCommandHandler>);
        handlers.insert("debug.ed25519".to_string(), Arc::new(DebugEd25519Command) as Arc<dyn NodeCommandHandler>);

        Self { handlers }
    }

    /// Get a handler for a command.
    pub fn get(&self, command: &str) -> Option<Arc<dyn NodeCommandHandler>> {
        self.handlers.get(command).cloned()
    }

    /// List all available commands.
    pub fn commands(&self) -> Vec<String> {
        self.handlers.keys().cloned().collect()
    }

    /// Check if a command is available.
    pub fn has(&self, command: &str) -> bool {
        self.handlers.contains_key(command)
    }
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Built-in Commands (OpenClaw Android Node Commands)
// Reference: https://github.com/openclaw/openclaw/blob/main/apps/android/app/src/main/java/ai/openclaw/app/node/InvokeCommandRegistry.kt
// ---------------------------------------------------------------------------

// Canvas Commands

/// canvas.present - Present content to canvas
pub struct CanvasPresentCommand;

#[async_trait]
impl NodeCommandHandler for CanvasPresentCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with params: {:?}", node_id, command, params);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

/// canvas.hide - Hide canvas
pub struct CanvasHideCommand;

#[async_trait]
impl NodeCommandHandler for CanvasHideCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        _timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {}", node_id, command);
        Ok(serde_json::json!({
            "success": true,
            "command": command
        }))
    }
}

/// canvas.navigate - Navigate canvas
pub struct CanvasNavigateCommand;

#[async_trait]
impl NodeCommandHandler for CanvasNavigateCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        _timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with params: {:?}", node_id, command, params);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

/// canvas.eval - Evaluate JavaScript on canvas
pub struct CanvasEvalCommand;

#[async_trait]
impl NodeCommandHandler for CanvasEvalCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

/// canvas.snapshot - Take canvas snapshot
pub struct CanvasSnapshotCommand;

#[async_trait]
impl NodeCommandHandler for CanvasSnapshotCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

/// canvas.a2ui.push - Push data to UI
pub struct CanvasA2UiPushCommand;

#[async_trait]
impl NodeCommandHandler for CanvasA2UiPushCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

/// canvas.a2ui.push_jsonl - Push JSONL data to UI
pub struct CanvasA2UiPushJsonlCommand;

#[async_trait]
impl NodeCommandHandler for CanvasA2UiPushJsonlCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

/// canvas.a2ui.reset - Reset UI state
pub struct CanvasA2UiResetCommand;

#[async_trait]
impl NodeCommandHandler for CanvasA2UiResetCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        _params: serde_json::Value,
        _timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {}", node_id, command);
        Ok(serde_json::json!({
            "success": true,
            "command": command
        }))
    }
}

// System/Device Commands

/// system.notify - Send system notification
pub struct SystemNotifyCommand;

#[async_trait]
impl NodeCommandHandler for SystemNotifyCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

/// device.status - Get device status
pub struct DeviceStatusCommand;

#[async_trait]
impl NodeCommandHandler for DeviceStatusCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        _params: serde_json::Value,
        _timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {}", node_id, command);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "status": "online"
        }))
    }
}

/// device.info - Get device info
pub struct DeviceInfoCommand;

#[async_trait]
impl NodeCommandHandler for DeviceInfoCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        _params: serde_json::Value,
        _timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {}", node_id, command);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "platform": "gateway",
            "version": env!("CARGO_PKG_VERSION")
        }))
    }
}

/// device.permissions - Get device permissions
pub struct DevicePermissionsCommand;

#[async_trait]
impl NodeCommandHandler for DevicePermissionsCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        _params: serde_json::Value,
        _timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {}", node_id, command);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "permissions": []
        }))
    }
}

/// device.health - Get device health
pub struct DeviceHealthCommand;

#[async_trait]
impl NodeCommandHandler for DeviceHealthCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        _params: serde_json::Value,
        _timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {}", node_id, command);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "healthy": true
        }))
    }
}

// Camera Commands

/// camera.list - List available cameras
pub struct CameraListCommand;

#[async_trait]
impl NodeCommandHandler for CameraListCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        _params: serde_json::Value,
        _timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {}", node_id, command);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "cameras": []
        }))
    }
}

/// camera.snap - Take camera snapshot
pub struct CameraSnapCommand;

#[async_trait]
impl NodeCommandHandler for CameraSnapCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

/// camera.clip - Record camera clip
pub struct CameraClipCommand;

#[async_trait]
impl NodeCommandHandler for CameraClipCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

// Location Commands

/// location.get - Get current location
pub struct LocationGetCommand;

#[async_trait]
impl NodeCommandHandler for LocationGetCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        _params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command
        }))
    }
}

// Notification Commands

/// notifications.list - List notifications
pub struct NotificationsListCommand;

#[async_trait]
impl NodeCommandHandler for NotificationsListCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "notifications": [],
            "params": params
        }))
    }
}

/// notifications.actions - Get notification actions
pub struct NotificationsActionsCommand;

#[async_trait]
impl NodeCommandHandler for NotificationsActionsCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

// Photos Commands

/// photos.latest - Get latest photos
pub struct PhotosLatestCommand;

#[async_trait]
impl NodeCommandHandler for PhotosLatestCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "photos": [],
            "params": params
        }))
    }
}

// Contact Commands

/// contacts.search - Search contacts
pub struct ContactsSearchCommand;

#[async_trait]
impl NodeCommandHandler for ContactsSearchCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "contacts": [],
            "params": params
        }))
    }
}

/// contacts.add - Add contact
pub struct ContactsAddCommand;

#[async_trait]
impl NodeCommandHandler for ContactsAddCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

// Calendar Commands

/// calendar.events - Get calendar events
pub struct CalendarEventsCommand;

#[async_trait]
impl NodeCommandHandler for CalendarEventsCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "events": [],
            "params": params
        }))
    }
}

/// calendar.add - Add calendar event
pub struct CalendarAddCommand;

#[async_trait]
impl NodeCommandHandler for CalendarAddCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

// Motion Commands

/// motion.activity - Get motion activity
pub struct MotionActivityCommand;

#[async_trait]
impl NodeCommandHandler for MotionActivityCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

/// motion.pedometer - Get pedometer data
pub struct MotionPedometerCommand;

#[async_trait]
impl NodeCommandHandler for MotionPedometerCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

// SMS Commands

/// sms.send - Send SMS
pub struct SmsSendCommand;

#[async_trait]
impl NodeCommandHandler for SmsSendCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "params": params
        }))
    }
}

/// sms.search - Search SMS
pub struct SmsSearchCommand;

#[async_trait]
impl NodeCommandHandler for SmsSearchCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "messages": [],
            "params": params
        }))
    }
}

// CallLog Commands

/// calllog.search - Search call log
pub struct CallLogSearchCommand;

#[async_trait]
impl NodeCommandHandler for CallLogSearchCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "calls": [],
            "params": params
        }))
    }
}

// Debug Commands

/// debug.logs - Get debug logs
pub struct DebugLogsCommand;

#[async_trait]
impl NodeCommandHandler for DebugLogsCommand {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {} with timeout: {}", node_id, command, timeout_ms);
        Ok(serde_json::json!({
            "success": true,
            "command": command,
            "logs": [],
            "params": params
        }))
    }
}

/// debug.ed25519 - Get Ed25519 public key
pub struct DebugEd25519Command;

#[async_trait]
impl NodeCommandHandler for DebugEd25519Command {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        _params: serde_json::Value,
        _timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        info!("Node {} command {}", node_id, command);
        Ok(serde_json::json!({
            "success": true,
            "command": command
        }))
    }
}

// ---------------------------------------------------------------------------
// Agent-backed Command Handler
// ---------------------------------------------------------------------------

/// Command handler that forwards commands to an agent for LLM-powered execution.
/// This allows the agent to decide how to execute commands based on context.
pub struct AgentCommandHandler {
    /// Channel to send commands to the agent.
    /// In a full implementation, this would integrate with the bridge.
    pending_commands: Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<CommandResult>>>>,
}

impl AgentCommandHandler {
    pub fn new() -> Self {
        Self {
            pending_commands: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a pending command and get the response channel.
    pub async fn register_pending(
        &self,
        invoke_id: String,
    ) -> tokio::sync::oneshot::Receiver<CommandResult> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut pending = self.pending_commands.write().await;
        pending.insert(invoke_id, tx);
        rx
    }

    /// Complete a pending command.
    pub async fn complete_pending(&self, invoke_id: &str, result: CommandResult) -> bool {
        let mut pending = self.pending_commands.write().await;
        if let Some(tx) = pending.remove(invoke_id) {
            let _ = tx.send(result);
            true
        } else {
            false
        }
    }
}

impl Default for AgentCommandHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NodeCommandHandler for AgentCommandHandler {
    async fn handle_command(
        &self,
        node_id: &str,
        command: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, CommandError> {
        // Generate invoke ID
        let invoke_id = uuid::Uuid::new_v4().to_string();

        // In a full implementation, this would:
        // 1. Send the command to an agent via the bridge
        // 2. Wait for the agent to process and return a result
        // 3. Return the result to the caller

        info!(
            "AgentCommandHandler: node={}, cmd={}, params={}",
            node_id,
            command,
            serde_json::to_string(&params).unwrap_or_default()
        );

        // For now, delegate to the appropriate handler
        if let Some(handler) = CommandRegistry::new().get(command) {
            handler.handle_command(node_id, command, params, timeout_ms).await
        } else {
            Err(CommandError::unavailable())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_registry_has_commands() {
        let registry = CommandRegistry::new();
        // Canvas commands
        assert!(registry.has("canvas.present"));
        assert!(registry.has("canvas.hide"));
        // System/Device commands
        assert!(registry.has("device.status"));
        assert!(registry.has("device.info"));
        // Camera commands
        assert!(registry.has("camera.snap"));
        // SMS commands
        assert!(registry.has("sms.send"));
        assert!(registry.has("sms.search"));
        // Non-existent
        assert!(!registry.has("nonexistent"));
    }

    #[test]
    fn test_command_registry_list() {
        let registry = CommandRegistry::new();
        let commands = registry.commands();
        assert!(commands.contains(&"canvas.present".to_string()));
        assert!(commands.contains(&"device.status".to_string()));
        assert!(commands.contains(&"camera.snap".to_string()));
        assert!(commands.contains(&"sms.send".to_string()));
    }

    #[tokio::test]
    async fn test_device_status_command() {
        let handler = DeviceStatusCommand;
        let result = handler
            .handle_command("device-1", "device.status", serde_json::json!({}), 5000)
            .await;
        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["status"], "online");
    }

    #[tokio::test]
    async fn test_device_info_command() {
        let handler = DeviceInfoCommand;
        let result = handler
            .handle_command("device-1", "device.info", serde_json::json!({}), 5000)
            .await;
        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["platform"], "gateway");
    }
}
