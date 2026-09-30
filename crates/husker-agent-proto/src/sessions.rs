use serde::{Deserialize, Serialize};

use crate::ExecRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStartRequest {
    pub id: String,
    pub exec: ExecRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Running,
    Completed,
    Cancelled,
    TimedOut,
    Interrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
pub struct SessionInfo {
    pub id: String,
    /// Executable only. Arguments and environment are never persisted here.
    pub command: String,
    pub state: SessionState,
    pub created_at: u64,
    pub finished_at: Option<u64>,
    pub exit_code: Option<i32>,
    pub output_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
pub struct SessionEvent {
    /// Monotonic cursor starting at 1; pass it as `after` to resume reading.
    pub sequence: u64,
    pub stream: String,
    /// Base64-encoded bytes, preserving non-UTF-8 command output.
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
pub struct SessionEventsResponse {
    pub session: SessionInfo,
    pub events: Vec<SessionEvent>,
    pub next_cursor: u64,
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentRequest, AgentResponse};

    #[test]
    fn session_messages_are_framed_objects_and_roundtrip() {
        let info = SessionInfo {
            id: "id".into(),
            command: "sh".into(),
            state: SessionState::Running,
            created_at: 10,
            finished_at: None,
            exit_code: None,
            output_truncated: false,
        };
        let responses = vec![
            AgentResponse::Session(info.clone()),
            AgentResponse::Sessions {
                sessions: vec![info.clone()],
            },
            AgentResponse::SessionEvents(SessionEventsResponse {
                session: info,
                events: vec![SessionEvent {
                    sequence: 1,
                    stream: "stdout".into(),
                    data: "AP8=".into(),
                }],
                next_cursor: 1,
                has_more: true,
            }),
            AgentResponse::SessionRemoved,
            AgentResponse::TunnelReady,
        ];
        for response in responses {
            let value = serde_json::to_value(response).unwrap();
            assert!(value.is_object());
            let decoded: AgentResponse = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        }
        for request in [
            AgentRequest::SessionStart(SessionStartRequest {
                id: "id".into(),
                exec: ExecRequest {
                    command: "sh".into(),
                    args: vec!["-c".into(), "echo hello".into()],
                    working_dir: None,
                    env: vec![],
                    timeout_secs: Some(60),
                },
            }),
            AgentRequest::SessionList,
            AgentRequest::SessionGet { id: "id".into() },
            AgentRequest::SessionEvents {
                id: "id".into(),
                after: 42,
            },
            AgentRequest::SessionCancel { id: "id".into() },
            AgentRequest::SessionRemove { id: "id".into() },
            AgentRequest::Tunnel { port: 3000 },
        ] {
            let value = serde_json::to_value(request).unwrap();
            let decoded: AgentRequest = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        }
        for (state, value) in [
            (SessionState::Running, "running"),
            (SessionState::Completed, "completed"),
            (SessionState::Cancelled, "cancelled"),
            (SessionState::TimedOut, "timed_out"),
            (SessionState::Interrupted, "interrupted"),
        ] {
            assert_eq!(serde_json::to_value(state).unwrap(), value);
            assert_eq!(
                serde_json::from_value::<SessionState>(value.into()).unwrap(),
                state
            );
        }
    }
}
