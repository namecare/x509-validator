//! Shared input-shaping helpers for the fuzzers.
pub fn frames(data: &[u8], max_frames: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = data;

    while out.len() < max_frames {
        let Some((len_bytes, body)) = rest.split_at_checked(2) else {
            break;
        };
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

        match body.split_at_checked(len) {
            Some((frame, remainder)) => {
                out.push(frame);
                rest = remainder;
            }

            None => {
                out.push(body);
                break;
            }
        }
    }

    out
}
