use {
    crate::{
        args::ProcessedArgs,
        errors::{Context, Result, bail},
        files,
    },
    futures::{StreamExt, stream},
    hickory_resolver::{
        TokioResolver,
        config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts},
        net::runtime::TokioRuntimeProvider,
    },
    log::debug,
    std::{
        collections::{HashMap, HashSet},
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    },
};

pub const DNS_TIMEOUT: Duration = Duration::from_secs(1);
pub const DNS_ATTEMPTS: usize = 2;

pub fn parse_resolver_ips<I, S>(entries: I) -> Result<Vec<Ipv4Addr>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut ips = Vec::new();
    for entry in entries {
        let entry = entry.as_ref().trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        let ip = entry.parse::<Ipv4Addr>().with_context(|| {
            format!("Error parsing the {entry} IP from resolvers list, only IPv4 are allowed")
        })?;
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    if ips.is_empty() {
        bail!("The resolvers list is empty");
    }
    Ok(ips)
}

pub fn resolver_ips(args: &ProcessedArgs) -> Result<Vec<Ipv4Addr>> {
    if args.custom_resolvers {
        let entries = files::return_file_targets(&args.resolvers, args.quiet_flag)?;
        parse_resolver_ips(entries)
    } else {
        parse_resolver_ips(&args.resolvers)
    }
}

pub fn build_resolver(resolver_ips: &[Ipv4Addr]) -> Result<TokioResolver> {
    if resolver_ips.is_empty() {
        bail!("No DNS resolvers configured");
    }
    let name_servers = resolver_ips
        .iter()
        .map(|ip| NameServerConfig::udp(IpAddr::V4(*ip)))
        .collect();

    let mut opts = ResolverOpts::default();
    opts.timeout = DNS_TIMEOUT;
    opts.attempts = DNS_ATTEMPTS;
    opts.ip_strategy = LookupIpStrategy::Ipv4Only;
    opts.num_concurrent_reqs = 1;
    // Every target is a FQDN, never append search domains.
    opts.ndots = 0;
    // Static entries in /etc/hosts must not override the public resolution.
    opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;

    let mut builder = TokioResolver::builder_with_config(
        ResolverConfig::from_name_servers(name_servers),
        TokioRuntimeProvider::default(),
    );
    *builder.options_mut() = opts;
    builder.build().context("Error building the DNS resolver")
}

pub async fn resolve_ipv4(resolver: &TokioResolver, target: &str) -> Option<Ipv4Addr> {
    let fqdn = if target.ends_with('.') {
        target.to_owned()
    } else {
        format!("{target}.")
    };
    match resolver.lookup_ip(fqdn.as_str()).await {
        Ok(lookup) => lookup.iter().find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }),
        Err(e) => {
            debug!("{target} did not resolve: {e}");
            None
        }
    }
}

pub fn resolve_all(
    resolver: &TokioResolver,
    targets: &HashSet<String>,
    concurrency: usize,
) -> Result<HashMap<String, Option<Ipv4Addr>>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Error starting the async runtime")?;

    let concurrency = concurrency.max(1);
    let resolved = runtime.block_on(async {
        stream::iter(targets.iter())
            .map(|target| async move { (target.clone(), resolve_ipv4(resolver, target).await) })
            .buffer_unordered(concurrency)
            .collect::<HashMap<String, Option<Ipv4Addr>>>()
            .await
    });
    Ok(resolved)
}

#[must_use]
pub fn is_scannable(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resolvers_accepts_ipv4_and_skips_noise() {
        let ips = parse_resolver_ips(["1.1.1.1", " 8.8.8.8 ", "", "# comment", "1.1.1.1"]).unwrap();
        assert_eq!(
            ips,
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
        );
    }

    #[test]
    fn parse_resolvers_rejects_invalid_entries() {
        assert!(parse_resolver_ips(["1.1.1.1", "not-an-ip"]).is_err());
        assert!(parse_resolver_ips(["2606:4700:4700::1111"]).is_err());
        assert!(parse_resolver_ips(Vec::<&str>::new()).is_err());
        assert!(parse_resolver_ips(["", "#x"]).is_err());
    }

    #[test]
    fn scannable_ips() {
        for ip in ["45.33.32.156", "93.184.216.34", "1.1.1.1", "8.8.8.8"] {
            assert!(is_scannable(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.1",
            "100.64.0.1",
        ] {
            assert!(!is_scannable(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn build_resolver_requires_servers() {
        assert!(build_resolver(&[]).is_err());
        assert!(build_resolver(&[Ipv4Addr::new(1, 1, 1, 1)]).is_ok());
    }

    #[test]
    fn resolve_all_with_unreachable_resolver_returns_none_for_every_target() {
        // TEST-NET-1 never answers.
        let resolver = build_resolver(&[Ipv4Addr::new(192, 0, 2, 1)]).unwrap();
        let targets: HashSet<String> = ["a.invalid", "b.invalid"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let resolved = resolve_all(&resolver, &targets, 4).unwrap();
        assert_eq!(resolved.len(), 2);
        assert!(resolved.values().all(Option::is_none));
    }
}
