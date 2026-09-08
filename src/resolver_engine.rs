use {
    crate::{
        args::ProcessedArgs,
        errors::{Context, Result, bail},
        files, logic, networking,
        nmap::{self, Nmaprun, ScanError, ScanOptions},
        structs::{ResolvData, ScanStatus},
    },
    log::{debug, error, info, warn},
    prettytable::{Table, row},
    rayon::prelude::*,
    std::{
        collections::{BTreeMap, HashMap, HashSet},
        net::Ipv4Addr,
    },
};

pub type ScanResults = BTreeMap<String, ResolvData>;

pub fn parallel_resolver_all(args: &mut ProcessedArgs) -> Result<()> {
    if !files::check_full_path(&args.logs_dir) {
        bail!(
            "The logs directory {} does not exist and could not be created.",
            args.logs_dir
        );
    }

    // Fail before spending time on DNS when Nmap is not usable.
    match nmap::check_nmap_available() {
        Ok(version) => debug!("Using {version}"),
        Err(e) => bail!("{e}. Nmap must be installed and in the PATH."),
    }

    let resolver_ips = networking::resolver_ips(args)?;
    let resolver = networking::build_resolver(&resolver_ips)?;

    if !args.quiet_flag {
        info!(
            "Performing parallel resolution for {} targets with {} threads, it will take a while...\n",
            args.targets.len(),
            args.threads
        );
    }

    let resolved = networking::resolve_all(&resolver, &args.targets, args.threads)?;
    let data = scan_engine(args, resolved, &resolver_ips)?;

    print_results(args, &data)?;

    if args.no_keep_nmap_logs {
        // Fails when the CSV output or anything else lives in there.
        if std::fs::remove_dir(&args.logs_dir).is_ok() {
            debug!("Removed empty logs directory {}", args.logs_dir);
        }
    }

    if !args.quiet_flag {
        info!(
            "Job finished in {:.1} seconds.\n",
            args.time_wasted.elapsed().as_secs_f64()
        );
        if args.with_output {
            info!("Logfile saved in {}\n\n", args.file_name);
        }
        println!();
    }
    Ok(())
}

pub fn scan_engine(
    args: &ProcessedArgs,
    resolved: HashMap<String, Option<Ipv4Addr>>,
    resolver_ips: &[Ipv4Addr],
) -> Result<ScanResults> {
    let unique_ips: HashSet<Ipv4Addr> = resolved.values().flatten().copied().collect();
    let scannable: Vec<Ipv4Addr> = unique_ips
        .iter()
        .copied()
        .filter(|ip| networking::is_scannable(*ip))
        .collect();

    let resolved_count = resolved.values().filter(|ip| ip.is_some()).count();
    if !args.quiet_flag {
        info!(
            "Resolved {resolved_count} of {} targets to {} unique IPs, {} of them are public and will be scanned.\n",
            resolved.len(),
            unique_ips.len(),
            scannable.len()
        );
    }

    if scannable.is_empty() {
        let mut found: Vec<String> = unique_ips.iter().map(ToString::to_string).collect();
        found.sort();
        bail!("No valid IPs found for scanning. IPs found: {found:?}");
    }

    let opts = ScanOptions {
        min_rate: &args.min_rate,
        ports: &args.ports,
        fast_scan: args.fast_scan,
        resolvers: resolver_ips,
    };

    let scans: Vec<(Ipv4Addr, Result<Nmaprun, ScanError>)> = scannable
        .par_iter()
        .map(|ip| {
            let filename = format!("{}/{ip}.xml", args.logs_dir);
            let result = nmap::get_nmap_data(&filename, &ip.to_string(), &opts);
            if result.is_ok()
                && args.no_keep_nmap_logs
                && let Err(e) = std::fs::remove_file(&filename)
            {
                error!("Error removing file {filename}: {e}");
            }
            (*ip, result)
        })
        .collect();

    let mut ports_by_ip: HashMap<Ipv4Addr, Vec<nmap::Port>> = HashMap::with_capacity(scans.len());
    let mut failures = 0usize;
    for (ip, result) in scans {
        match result {
            Ok(run) => {
                ports_by_ip.insert(ip, nmap::open_ports(&run));
            }
            Err(ScanError::Spawn(e)) => {
                bail!("Could not execute nmap while scanning {ip}: {e}");
            }
            Err(e) => {
                failures += 1;
                error!("Error scanning the IP {ip}. Description: {e}\n");
            }
        }
    }

    if failures > 0 && failures == scannable.len() {
        bail!(
            "Every Nmap scan failed ({failures} of {failures}). Nmap needs root/administrator privileges for the SYN scan."
        );
    }
    if failures > 0 {
        warn!("{failures} of {} scans failed.\n", scannable.len());
    }

    Ok(resolved
        .into_iter()
        .map(|(target, ip)| {
            let (status, ports_data) = match ip {
                Some(ip) if !networking::is_scannable(ip) => (ScanStatus::Skipped, Vec::new()),
                Some(ip) => ports_by_ip
                    .get(&ip)
                    .map_or((ScanStatus::Failed, Vec::new()), |ports| {
                        (ScanStatus::Scanned, ports.clone())
                    }),
                None => (ScanStatus::Scanned, Vec::new()),
            };
            (
                target,
                ResolvData {
                    ip,
                    ports_data,
                    status,
                },
            )
        })
        .collect())
}

#[must_use]
pub fn build_table(data: &ScanResults) -> Table {
    let mut table = Table::new();
    table.set_titles(row![bcFg => "HOST", "IP", "OPEN PORTS", "SERVICES"]);
    for (target, resolv_data) in data {
        if resolv_data.ip.is_none() {
            continue;
        }
        let mut services_table = Table::new();
        for port_data in &resolv_data.ports_data {
            services_table.add_row(row![bc => format!("PORT => {}", port_data.portid)]);
            services_table.add_row(row![c => format!("SERVICE: {}", port_data.service_name())]);
            services_table.add_row(row![c => format!("VERSION: {}", port_data.service_version())]);
            services_table.add_row(row![c => format!("PRODUCT: {}", port_data.service_product())]);
            services_table.add_row(row![c => format!("OS TYPE: {}", port_data.service_ostype())]);
            services_table
                .add_row(row![c => format!("EXTRA INFO: {}", port_data.service_extrainfo())]);
        }
        table.add_row(row![d =>
            target,
            logic::null_ip_checker(&resolv_data.ip_string()),
            resolv_data.ports_column(),
            services_table,
        ]);
    }
    table
}

#[must_use]
pub fn raw_lines(data: &ScanResults) -> Vec<String> {
    let mut lines = Vec::new();
    for (target, resolv_data) in data {
        let Some(ip) = resolv_data.ip else { continue };
        for p in &resolv_data.ports_data {
            lines.push(format!(
                "{target},{ip},{},{},{},{},{},{}",
                p.portid,
                p.service_name(),
                p.service_version(),
                p.service_product(),
                p.service_ostype(),
                p.service_extrainfo()
            ));
        }
    }
    lines
}

#[must_use]
pub fn url_lines(data: &ScanResults) -> Vec<String> {
    let mut lines = Vec::new();
    for (target, resolv_data) in data {
        if resolv_data.ip.is_none() {
            continue;
        }
        for p in &resolv_data.ports_data {
            lines.push(format!("{target}:{}", p.portid));
        }
    }
    lines
}

fn print_results(args: &ProcessedArgs, data: &ScanResults) -> Result<()> {
    let table = build_table(data);

    if args.raw_output {
        if !args.quiet_flag {
            println!("HOST,IP,PORT,SERVICE,VERSION,PRODUCT,OS,EXTRAINFO");
        }
        for line in raw_lines(data) {
            println!("{line}");
        }
    } else if args.url_output {
        if !args.quiet_flag {
            println!("HOST:IP");
        }
        for line in url_lines(data) {
            println!("{line}");
        }
    } else if !args.quiet_flag {
        table.printstd();
    }

    if args.with_output {
        let file = files::return_output_file(&args.file_name)?;
        files::table_to_file(&table, file).with_context(|| {
            format!(
                "An error occurred while writing the output file {}",
                args.file_name
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmap::{Port, Service, State};
    use clap::Parser;

    fn port(id: &str, name: &str, version: Option<&str>) -> Port {
        Port {
            protocol: "tcp".into(),
            portid: id.into(),
            state: State {
                state: "open".into(),
                reason: "syn-ack".into(),
                reason_ttl: "53".into(),
            },
            service: Some(Service {
                name: name.into(),
                method: "table".into(),
                conf: "3".into(),
                product: None,
                ostype: None,
                version: version.map(str::to_string),
                extrainfo: None,
            }),
        }
    }

    fn sample() -> ScanResults {
        let mut data = ScanResults::new();
        data.insert(
            "b.example.com".into(),
            ResolvData {
                ip: Some(Ipv4Addr::new(45, 33, 32, 156)),
                ports_data: vec![port("22", "ssh", Some("8.9")), port("80", "http", None)],
                status: ScanStatus::Scanned,
            },
        );
        data.insert(
            "a.example.com".into(),
            ResolvData {
                ip: Some(Ipv4Addr::new(45, 33, 32, 156)),
                ports_data: vec![port("22", "ssh", Some("8.9")), port("80", "http", None)],
                status: ScanStatus::Scanned,
            },
        );
        data.insert(
            "unresolved.example.com".into(),
            ResolvData {
                ip: None,
                ports_data: vec![],
                status: ScanStatus::Scanned,
            },
        );
        data.insert(
            "private.example.com".into(),
            ResolvData {
                ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
                ports_data: vec![],
                status: ScanStatus::Skipped,
            },
        );
        data.insert(
            "failed.example.com".into(),
            ResolvData {
                ip: Some(Ipv4Addr::new(198, 51, 100, 7)),
                ports_data: vec![],
                status: ScanStatus::Failed,
            },
        );
        data.insert(
            "closed.example.com".into(),
            ResolvData {
                ip: Some(Ipv4Addr::new(198, 51, 100, 8)),
                ports_data: vec![],
                status: ScanStatus::Scanned,
            },
        );
        data
    }

    #[test]
    fn raw_output_is_sorted_and_skips_unresolved() {
        let lines = raw_lines(&sample());
        assert_eq!(
            lines,
            vec![
                "a.example.com,45.33.32.156,22,ssh,8.9,NULL,NULL,NULL",
                "a.example.com,45.33.32.156,80,http,NULL,NULL,NULL,NULL",
                "b.example.com,45.33.32.156,22,ssh,8.9,NULL,NULL,NULL",
                "b.example.com,45.33.32.156,80,http,NULL,NULL,NULL,NULL",
            ]
        );
    }

    #[test]
    fn url_output() {
        assert_eq!(
            url_lines(&sample()),
            vec![
                "a.example.com:22",
                "a.example.com:80",
                "b.example.com:22",
                "b.example.com:80"
            ]
        );
    }

    #[test]
    fn table_has_one_row_per_resolved_target() {
        let table = build_table(&sample());
        assert_eq!(table.len(), 5);
        let mut csv = Vec::new();
        table.to_csv(&mut csv).unwrap();
        let csv = String::from_utf8(csv).unwrap();
        assert!(csv.starts_with("HOST,IP,OPEN PORTS,SERVICES\n"), "{csv}");
        assert!(csv.contains("a.example.com,45.33.32.156,22;80,"), "{csv}");
        assert!(
            csv.contains("closed.example.com,198.51.100.8,NULL,"),
            "{csv}"
        );
        assert!(
            csv.contains("private.example.com,10.0.0.1,NOT SCANNED,"),
            "{csv}"
        );
        assert!(
            csv.contains("failed.example.com,198.51.100.7,SCAN FAILED,"),
            "{csv}"
        );
        assert!(!csv.contains("unresolved"), "{csv}");
    }

    #[test]
    fn scan_engine_fails_when_nothing_is_scannable() {
        let args = crate::args::Args::try_parse_from(["unimap", "-t", "a.com", "-q"])
            .unwrap()
            .into_processed_args();
        let mut resolved = HashMap::new();
        resolved.insert("a.com".to_string(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        resolved.insert("b.com".to_string(), None);
        let err = scan_engine(&args, resolved, &[]).unwrap_err().to_string();
        assert!(err.contains("No valid IPs found"), "{err}");
        assert!(err.contains("10.0.0.1"), "{err}");
    }
}
