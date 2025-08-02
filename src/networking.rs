use {
    crate::{args::ProcessedArgs, files},
    hickory_resolver::{
        config::{NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts},
        name_server::TokioConnectionProvider,
        proto::xfer::Protocol,
        TokioResolver,
    },
    std::{collections::HashSet, net::SocketAddr},
};

pub fn get_records(resolver: &TokioResolver, domain: &str) -> String {
    futures::executor::block_on(resolver.ipv4_lookup(domain)).map_or_else(
        |_| String::new(),
        |ips| {
            ips.iter()
                .map(std::string::ToString::to_string)
                .next()
                .expect("Failed to get IPV4.")
        },
    )
}

pub fn get_resolver(nameserver_ips: HashSet<SocketAddr>, opts: ResolverOpts) -> TokioResolver {
    let mut name_servers = NameServerConfigGroup::with_capacity(nameserver_ips.len());
    name_servers.extend(
        nameserver_ips
            .into_iter()
            .map(|socket_addr| NameServerConfig::new(socket_addr, Protocol::Udp)),
    );

    TokioResolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], name_servers),
        TokioConnectionProvider::default(),
    )
    .with_options(opts)
    .build()
}

pub fn return_socket_address(args: &ProcessedArgs) -> HashSet<SocketAddr> {
    let mut resolver_ips = HashSet::new();
    if args.custom_resolvers {
        for r in &files::return_file_targets(args, args.resolvers.clone()) {
            let server = r.to_owned() + ":53";
            let socket_addr = SocketAddr::V4(match server.parse() {
                Ok(a) => a,
                Err(e) => unreachable!(
                    "Error parsing the server {}, only IPv4 are allowed. Error: {}",
                    r, e
                ),
            });
            resolver_ips.insert(socket_addr);
        }
    } else {
        for r in &args.resolvers {
            let server = r.to_owned() + ":53";
            let socket_addr = SocketAddr::V4(match server.parse() {
                Ok(a) => a,
                Err(e) => unreachable!(
                    "Error parsing the server {}, only IPv4 are allowed. Error: {}",
                    r, e
                ),
            });
            resolver_ips.insert(socket_addr);
        }
    }
    resolver_ips
}
