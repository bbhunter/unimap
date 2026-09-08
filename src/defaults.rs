pub const DEFAULT_THREADS: usize = 50;
/// Custom port ranges are heavier scans, so they get fewer threads by default.
pub const DEFAULT_THREADS_WITH_PORTS: usize = 30;
/// Below this many targets the pool is sized to the number of targets.
pub const THREADS_TARGETS_THRESHOLD: usize = 50;
pub const DEFAULT_LOGS_DIR: &str = "unimap_logs";

pub const IPV4_RESOLVERS: &[&str] = &[
    // Cloudflare
    "1.1.1.1",
    "1.0.0.1",
    // Google
    "8.8.8.8",
    "8.8.4.4",
    // Quad9
    "9.9.9.9",
    "149.112.112.112",
    // OpenDNS
    "208.67.222.222",
    "208.67.220.220",
    // Verisign
    "64.6.64.6",
    "64.6.65.6",
];

#[must_use]
pub fn ipv4_resolvers() -> Vec<String> {
    IPV4_RESOLVERS.iter().map(|s| (*s).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn builtin_resolvers_are_valid_public_ipv4() {
        let resolvers = ipv4_resolvers();
        assert_eq!(resolvers.len(), IPV4_RESOLVERS.len());
        for r in &resolvers {
            let ip: Ipv4Addr = r.parse().unwrap_or_else(|_| panic!("invalid resolver {r}"));
            assert!(!ip.is_private(), "resolver {r} must be public");
            assert!(!ip.is_loopback(), "resolver {r} must not be loopback");
        }
    }

    #[test]
    fn builtin_resolvers_have_no_duplicates() {
        let mut sorted = ipv4_resolvers();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), IPV4_RESOLVERS.len());
    }
}
