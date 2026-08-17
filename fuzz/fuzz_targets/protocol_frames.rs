#![no_main]

use husker_agent_proto::{AgentRequest, AgentResponse, decode_message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Both directions share framing but deserialize different tagged enums.
    // Every byte string must return a bounded result, never panic or allocate
    // according to an untrusted oversized prefix.
    let _ = decode_message::<AgentRequest>(data);
    let _ = decode_message::<AgentResponse>(data);
});
