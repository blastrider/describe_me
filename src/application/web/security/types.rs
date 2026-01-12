use std::{
    collections::hash_map::{DefaultHasher, RandomState},
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    net::IpAddr,
    sync::OnceLock,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(in crate::application::web) enum TokenKey {
    Anonymous,
    Fingerprint(u64),
}

pub(in crate::application::web) type TokenFingerprint = [u8; 16];

impl TokenKey {
    /// Empreinte keyed (secret runtime), stable uniquement pendant la vie du process.
    /// Ne doit pas être persistée.
    pub(in crate::application::web) fn from_value(token: &str) -> Self {
        TokenKey::Fingerprint(token_hash_state().hash_one(token))
    }
}

impl fmt::Display for TokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenKey::Anonymous => f.write_str("anon"),
            TokenKey::Fingerprint(fp) => write!(f, "fp:{fp:016x}"),
        }
    }
}

const TOKEN_KEY_PROBE: &str = "__token_key_probe__";

fn token_hash_state() -> &'static RandomState {
    static STATE: OnceLock<RandomState> = OnceLock::new();
    STATE.get_or_init(|| {
        let unkeyed = unkeyed_token_hash(TOKEN_KEY_PROBE);
        loop {
            let state = RandomState::new();
            if state.hash_one(TOKEN_KEY_PROBE) != unkeyed {
                return state;
            }
        }
    })
}

fn unkeyed_token_hash(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IpMatcher {
    Exact(IpAddr),
    Ipv4 { network: u32, mask: u32 },
    Ipv6 { network: u128, mask: u128 },
}

impl IpMatcher {
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("entrée vide".into());
        }

        if let Some((addr_part, prefix_part)) = raw.split_once('/') {
            let base_ip: IpAddr = addr_part
                .parse()
                .map_err(|_| format!("adresse IP invalide: '{addr_part}'"))?;
            let prefix: u8 = prefix_part
                .parse()
                .map_err(|_| format!("préfixe CIDR invalide: '{prefix_part}'"))?;

            match base_ip {
                IpAddr::V4(base) => {
                    if prefix > 32 {
                        return Err(format!("préfixe IPv4 invalide: {prefix} (max 32)"));
                    }
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u32::MAX.checked_shl((32 - prefix) as u32).unwrap_or(0)
                    };
                    let network = u32::from(base) & mask;
                    Ok(IpMatcher::Ipv4 { network, mask })
                }
                IpAddr::V6(base) => {
                    if prefix > 128 {
                        return Err(format!("préfixe IPv6 invalide: {prefix} (max 128)"));
                    }
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u128::MAX.checked_shl((128 - prefix) as u32).unwrap_or(0)
                    };
                    let network = u128::from(base) & mask;
                    Ok(IpMatcher::Ipv6 { network, mask })
                }
            }
        } else {
            let ip: IpAddr = raw
                .parse()
                .map_err(|_| format!("adresse IP invalide: '{raw}'"))?;
            Ok(IpMatcher::Exact(ip))
        }
    }

    pub(crate) fn matches(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (IpMatcher::Exact(expected), current) => *expected == current,
            (IpMatcher::Ipv4 { network, mask }, IpAddr::V4(current)) => {
                (u32::from(current) & mask) == *network
            }
            (IpMatcher::Ipv6 { network, mask }, IpAddr::V6(current)) => {
                (u128::from(current) & mask) == *network
            }
            _ => false,
        }
    }
}
