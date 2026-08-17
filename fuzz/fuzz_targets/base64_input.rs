#![no_main]

use husker_agent_proto::base64_decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let _ = base64_decode(input);
    }
});
