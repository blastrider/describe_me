use std::{collections::hash_map::DefaultHasher, hash::Hasher, net::IpAddr};

const SESSION_UA_MAX_LEN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientClaim(u64);

pub(super) fn compute_client_claim(ip: IpAddr, user_agent: Option<&str>) -> ClientClaim {
    let mut hasher = DefaultHasher::new();
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            hasher.write_u8(4);
            hasher.write(&octets[..3]);
        }
        IpAddr::V6(addr) => {
            let segments = addr.segments();
            hasher.write_u8(6);
            for segment in segments.iter().take(4) {
                hasher.write_u16(*segment);
            }
        }
    }

    let ua = user_agent.unwrap_or("").trim();
    let mut ua_bytes = Vec::with_capacity(SESSION_UA_MAX_LEN.min(ua.len()));
    for byte in ua.as_bytes().iter().take(SESSION_UA_MAX_LEN) {
        ua_bytes.push(byte.to_ascii_lowercase());
    }
    hasher.write_usize(ua_bytes.len());
    hasher.write(&ua_bytes);

    ClientClaim(hasher.finish())
}
