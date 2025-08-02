use {
    crate::{
        args::ProcessedArgs,
        errors::Result,
        files, logic, networking,
        nmap::{self, Nmaprun},
        structs::ResolvData,
    },
    hickory_resolver::config::{LookupIpStrategy, ResolverOpts},
    log::{error, info},
    prettytable,
    prettytable::Table,
    rayon::prelude::*,
    std::{
        collections::{HashMap, HashSet},
        net::Ipv4Addr,
        time::Duration,
    },
};

fn create_resolvers(args: &ProcessedArgs) -> Vec<Ipv4Addr> {
    let mut resolver_ips = Vec::new();
    if args.custom_resolvers {
        for r in &files::return_file_targets(args, args.resolvers.clone()) {
            match r.parse::<Ipv4Addr>() {
                Ok(ip) => resolver_ips.push(ip),
                Err(e) => {
                    error!("Error parsing the {r} IP from resolvers file to IP address. Please check and try again. Error: {e}\n");
                    std::process::exit(1)
                }
            }
        }
    } else {
        for r in &args.resolvers {
            match r.parse::<Ipv4Addr>() {
                Ok(ip) => resolver_ips.push(ip),
                Err(e) => {
                    error!("Error parsing the {r} IP from resolvers file to IP address. Please check and try again. Error: {e}\n");
                    std::process::exit(1)
                }
            }
        }
    }
    resolver_ips
}

pub fn parallel_resolver_all(args: &mut ProcessedArgs) -> Result<()> {
    if !files::check_full_path(&args.logs_dir) {
        error!("The logs directory {} does not exist.\n", args.logs_dir);
        std::process::exit(1)
    }

    if !args.quiet_flag {
        info!(
            "Performing parallel resolution for {} targets with {} threads, it will take a while...\n",
            args.targets.len(), args.threads
        );
    }

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(1);
    opts.ip_strategy = LookupIpStrategy::Ipv4Only;
    opts.num_concurrent_reqs = 1;

    let resolver = networking::get_resolver(networking::return_socket_address(args), opts);

    let data = parallel_resolver_engine(args, &args.targets, &resolver);

    let mut table = Table::new();
    table.set_titles(row![
        bcFg => "HOST",
       "IP",
       "OPEN PORTS",
       "SERVICES"
    ]);
    if args.raw_output && !args.quiet_flag {
        println!("HOST,IP,PORT,SERVICE,VERSION,PRODUCT,OS,EXTRAINFO");
    } else if args.url_output && !args.quiet_flag {
        println!("HOST:IP");
    }
    for (target, resolv_data) in &data {
        if !resolv_data.ip.is_empty() {
            if args.raw_output {
                for port_data in &resolv_data.ports_data {
                    println!(
                        "{},{},{},{},{},{},{},{}",
                        target,
                        resolv_data.ip,
                        port_data.portid,
                        port_data.service.clone().unwrap_or_default().name,
                        port_data
                            .clone()
                            .service
                            .unwrap_or_default()
                            .version
                            .unwrap_or_else(|| "NULL".to_string()),
                        port_data
                            .clone()
                            .service
                            .clone()
                            .unwrap_or_default()
                            .product
                            .unwrap_or_else(|| "NULL".to_string()),
                        port_data
                            .service
                            .clone()
                            .unwrap_or_default()
                            .ostype
                            .clone()
                            .unwrap_or_else(|| "NULL".to_string()),
                        port_data
                            .service
                            .clone()
                            .unwrap_or_default()
                            .extrainfo
                            .clone()
                            .unwrap_or_else(|| "NULL".to_string())
                    );
                }
            } else if args.url_output {
                for port_data in &resolv_data.ports_data {
                    println!("{}:{}", target, port_data.portid);
                }
            } else {
                let mut services_table = Table::new();
                for port_data in &resolv_data.ports_data {
                    services_table
                        .add_row(row![bc => &format!("PORT => {}", port_data.portid.clone())]);
                    services_table.add_row(
                    row![c => &format!("SERVICE: {}", port_data.service.clone().unwrap_or_default().name)],
                );
                    services_table.add_row(row![c => &format!("VERSION: {}" ,port_data
                .service.clone().unwrap_or_default()
                .version
                .clone()
                .unwrap_or_else(|| "NULL".to_string()))]);
                    services_table.add_row(row![c => &format!("PRODUCT: {}", port_data
                    .service.clone().unwrap_or_default()
                    .product
                    .clone()
                    .unwrap_or_else(|| "NULL".to_string()))]);
                    services_table.add_row(row![c => &format!("OS TYPE: {}", port_data
                    .service.clone().unwrap_or_default()
                    .ostype
                    .clone()
                    .unwrap_or_else(|| "NULL".to_string()))]);
                    services_table.add_row(row![c => &format!("EXTRA INFO: {}", port_data
                    .service.clone().unwrap_or_default()
                    .extrainfo
                    .clone()
                    .unwrap_or_else(|| "NULL".to_string()))]);
                }
                table.add_row(row![ d =>
                    target,
                    logic::null_ip_checker(&resolv_data.ip),
                    logic::return_ports_string(
                        &resolv_data
                            .ports_data
                            .iter()
                            .map(|f| f.portid.clone())
                            .collect(),
                    ),
                    services_table,
                ]);
            }
        }
    }

    if args.with_output
        && !args.targets.is_empty()
        && files::table_to_file(&table, files::return_output_file(args)).is_err()
        && !args.quiet_flag
    {
        error!(
            "An error occurred while writing the output file {}.\n",
            args.file_name
        );
    }
    if !args.quiet_flag && !args.raw_output && !args.url_output {
        table.printstd();
    }

    if (args.with_output || args.unique_output_flag) && !args.quiet_flag {
        info!(
            "Job finished in {} seconds.\n",
            args.time_wasted.elapsed().as_secs()
        );
        info!("Logfile saved in {}\n\n", args.file_name);
    }
    if !args.quiet_flag {
        println!();
    }
    Ok(())
}

fn parallel_resolver_engine(
    args: &ProcessedArgs,
    targets: &HashSet<String>,
    resolver: &hickory_resolver::TokioResolver,
) -> HashMap<String, ResolvData> {
    let resolv_data: HashMap<String, ResolvData> = targets
        .par_iter()
        .map(|target| {
            let fqdn_target = format!("{target}.");
            let mut resolv_data = ResolvData::default();
            resolv_data.ip = networking::get_records(resolver, &fqdn_target);
            (target.to_owned(), resolv_data)
        })
        .collect();

    let resolvers = create_resolvers(args);

    let mut nmap_ips: HashSet<String> = resolv_data
        .values()
        .map(|resolv_data| resolv_data.ip.clone())
        .collect();

    let nmap_ips_orig = nmap_ips.clone();

    nmap_ips.retain(|ip| {
        !ip.is_empty()
            && !ip.parse::<Ipv4Addr>().unwrap().is_private()
            && ip.parse::<Ipv4Addr>().is_ok()
    });

    if nmap_ips.is_empty() {
        error!("No valid IPs found for scanning. IPs found: {nmap_ips_orig:?}\n");
        std::process::exit(1)
    } else {
        let nmap_data: HashMap<String, Nmaprun> = nmap_ips
            .par_iter()
            .map(|ip| {
                let filename = format!("{}/{}.xml", &args.logs_dir, &ip);
                match nmap::get_nmap_data(
                    &filename,
                    ip,
                    &args.min_rate,
                    &args.ports,
                    args.fast_scan,
                    &resolvers,
                ) {
                    Ok(nmap_data) => {
                        nmap_data
                            .host
                            .clone()
                            .unwrap_or_default()
                            .ports
                            .unwrap_or_default()
                            .port
                            .retain(|f| f.state.state == "open");
                        if args.no_keep_nmap_logs && std::fs::remove_file(&filename).is_err() {
                            error!("Error removing filename {}.", &filename);
                        }
                        (ip.clone(), nmap_data)
                    }
                    Err(e) => {
                        error!("Error scanning the ip {}. Description: {}", &ip, e);
                        (String::new(), Nmaprun::default())
                    }
                }
            })
            .collect();

        // Delete the args.logs_dir directory if it's empty
        if args.no_keep_nmap_logs && std::fs::remove_dir(&args.logs_dir).is_err() {
            error!("Error removing directory {}.", &args.logs_dir);
        }

        resolv_data
            .iter()
            .map(|(target, resolv_data)| {
                (
                    target.clone(),
                    ResolvData {
                        ip: resolv_data.ip.clone(),
                        ports_data: if resolv_data.ip.is_empty() {
                            resolv_data.ports_data.clone()
                        } else {
                            nmap_data
                                .get_key_value(&resolv_data.ip)
                                .unwrap()
                                .1
                                .host
                                .clone()
                                .unwrap_or_default()
                                .ports
                                .unwrap_or_default()
                                .port
                        },
                    },
                )
            })
            .collect()
    }
}
