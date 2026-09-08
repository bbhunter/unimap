use {
    serde::{Deserialize, Serialize},
    std::{
        fmt, io,
        net::Ipv4Addr,
        path::Path,
        process::{Command, Stdio},
    },
};

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Nmaprun {
    #[serde(rename = "@scanner")]
    pub scanner: String,
    #[serde(rename = "@args")]
    pub args: String,
    #[serde(rename = "@start")]
    pub start: String,
    #[serde(rename = "@startstr")]
    pub startstr: String,
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@xmloutputversion")]
    pub xmloutputversion: String,
    pub host: Option<Host>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    #[serde(rename = "@starttime")]
    pub starttime: String,
    #[serde(rename = "@endtime")]
    pub endtime: String,
    pub status: Status,
    #[serde(default)]
    pub address: Vec<Address>,
    #[serde(default)]
    pub hostnames: Hostnames,
    pub ports: Option<Ports>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    #[serde(rename = "@state")]
    pub state: String,
    #[serde(rename = "@reason")]
    pub reason: String,
    #[serde(rename = "@reason_ttl")]
    pub reason_ttl: String,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    #[serde(rename = "@addr")]
    pub addr: Option<String>,
    #[serde(rename = "@addrtype")]
    pub addrtype: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hostnames {
    #[serde(default)]
    pub hostname: Vec<Hostname>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hostname {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@type")]
    pub type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ports {
    #[serde(default)]
    pub port: Vec<Port>,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Port {
    #[serde(rename = "@protocol")]
    pub protocol: String,
    #[serde(rename = "@portid")]
    pub portid: String,
    pub state: State,
    pub service: Option<Service>,
}

impl Port {
    #[must_use]
    pub fn service_name(&self) -> &str {
        self.service.as_ref().map_or("", |s| s.name.as_str())
    }
    #[must_use]
    pub fn service_version(&self) -> &str {
        self.service
            .as_ref()
            .and_then(|s| s.version.as_deref())
            .unwrap_or("NULL")
    }
    #[must_use]
    pub fn service_product(&self) -> &str {
        self.service
            .as_ref()
            .and_then(|s| s.product.as_deref())
            .unwrap_or("NULL")
    }
    #[must_use]
    pub fn service_ostype(&self) -> &str {
        self.service
            .as_ref()
            .and_then(|s| s.ostype.as_deref())
            .unwrap_or("NULL")
    }
    #[must_use]
    pub fn service_extrainfo(&self) -> &str {
        self.service
            .as_ref()
            .and_then(|s| s.extrainfo.as_deref())
            .unwrap_or("NULL")
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct State {
    #[serde(rename = "@state")]
    pub state: String,
    #[serde(rename = "@reason")]
    pub reason: String,
    #[serde(rename = "@reason_ttl")]
    pub reason_ttl: String,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@method")]
    pub method: String,
    #[serde(rename = "@conf")]
    pub conf: String,
    #[serde(rename = "@product")]
    pub product: Option<String>,
    #[serde(rename = "@ostype")]
    pub ostype: Option<String>,
    #[serde(rename = "@version")]
    pub version: Option<String>,
    #[serde(rename = "@extrainfo")]
    pub extrainfo: Option<String>,
}

#[derive(Debug)]
pub enum ScanError {
    Spawn(io::Error),
    /// Nmap exited with an error or wrote no XML. Carries its exit status and stderr.
    NoOutput(String),
    Parse(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "could not execute nmap: {e}"),
            Self::NoOutput(detail) => {
                write!(f, "nmap did not produce a valid XML output")?;
                if !detail.is_empty() {
                    write!(f, ": {detail}")?;
                }
                Ok(())
            }
            Self::Parse(e) => write!(f, "could not parse the nmap XML output: {e}"),
        }
    }
}

impl std::error::Error for ScanError {}

#[derive(Debug, Clone, Default)]
pub struct ScanOptions<'a> {
    pub min_rate: &'a str,
    pub ports: &'a str,
    pub fast_scan: bool,
    pub resolvers: &'a [Ipv4Addr],
}

/// The argument list without the program name.
#[must_use]
pub fn nmap_args(filename: &str, host: &str, opts: &ScanOptions<'_>) -> Vec<String> {
    let mut args: Vec<String> = Vec::with_capacity(20);
    if !opts.resolvers.is_empty() {
        let dns = opts
            .resolvers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        args.push("--dns-servers".into());
        args.push(dns);
    }
    args.extend(
        [
            "-Pn",
            "-sS",
            "--open",
            "-dd",
            "-T4",
            "--max-retries",
            "3",
            "-oX",
            filename,
        ]
        .iter()
        .map(|s| (*s).to_string()),
    );

    if !opts.min_rate.is_empty() {
        args.push("--min-rate".into());
        args.push(opts.min_rate.to_string());
    }

    if opts.fast_scan {
        args.push("--host-timeout".into());
        args.push("20m".into());
    } else {
        args.push("-sV".into());
    }

    if !opts.ports.is_empty() {
        args.push("-p".into());
        args.push(opts.ports.to_string());
    }

    args.push(host.to_string());
    args
}

pub fn parse_nmap_xml(xml: &str) -> Result<Nmaprun, ScanError> {
    serde_xml_rs::from_str(xml).map_err(|e| ScanError::Parse(e.to_string()))
}

/// Drops `open|filtered` and the like.
#[must_use]
pub fn open_ports(run: &Nmaprun) -> Vec<Port> {
    run.host
        .as_ref()
        .and_then(|h| h.ports.as_ref())
        .map(|p| {
            p.port
                .iter()
                .filter(|port| port.state.state == "open")
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

pub fn check_nmap_available() -> Result<String, ScanError> {
    let output = Command::new("nmap")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(ScanError::Spawn)?;
    let first_line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    Ok(first_line)
}

pub fn get_nmap_data(
    filename: &str,
    host: &str,
    opts: &ScanOptions<'_>,
) -> Result<Nmaprun, ScanError> {
    let path = Path::new(filename);
    // A leftover from a previous run would be reported as fresh data if this scan fails.
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| {
            ScanError::Parse(format!(
                "could not remove stale output file {filename}: {e}"
            ))
        })?;
    }

    let args = nmap_args(filename, host, opts);
    let output = Command::new("nmap")
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .map_err(ScanError::Spawn)?;

    if !output.status.success() || !path.is_file() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut lines: Vec<&str> = stderr
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .rev()
            .take(2)
            .collect();
        lines.reverse();
        let mut detail = lines.join(" ");
        if !output.status.success() {
            let code = output
                .status
                .code()
                .map_or_else(|| "signal".to_string(), |c| c.to_string());
            detail = format!("exit status {code}. {detail}").trim().to_string();
        }
        return Err(ScanError::NoOutput(detail));
    }

    let xml = std::fs::read_to_string(path).map_err(|e| ScanError::Parse(e.to_string()))?;
    parse_nmap_xml(&xml)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PATH is process-wide, tests that change it cannot overlap.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const FAST: &str = include_str!("../tests/fixtures/nmap_fast_scan.xml");
    const SERVICE: &str = include_str!("../tests/fixtures/nmap_service_scan.xml");
    const NO_OPEN: &str = include_str!("../tests/fixtures/nmap_no_open_ports.xml");

    #[test]
    fn parses_fast_scan_with_multiple_addresses_and_hostnames() {
        let run = parse_nmap_xml(FAST).unwrap();
        assert_eq!(run.scanner, "nmap");
        assert_eq!(run.version, "7.991");
        let host = run.host.as_ref().expect("host present");
        assert_eq!(host.status.state, "up");
        assert_eq!(host.address.len(), 2);
        assert_eq!(host.address[0].addr.as_deref(), Some("45.33.32.156"));
        assert_eq!(host.hostnames.hostname.len(), 2);
        assert_eq!(host.ports.as_ref().unwrap().port.len(), 3);

        let open = open_ports(&run);
        let ids: Vec<&str> = open.iter().map(|p| p.portid.as_str()).collect();
        assert_eq!(ids, vec!["22", "80"], "open|filtered must be dropped");
        assert_eq!(open[0].service_name(), "ssh");
        assert_eq!(open[0].service_version(), "NULL");
        assert_eq!(open[0].service_product(), "NULL");
    }

    #[test]
    fn parses_service_scan() {
        let run = parse_nmap_xml(SERVICE).unwrap();
        let open = open_ports(&run);
        assert_eq!(open.len(), 1);
        let p = &open[0];
        assert_eq!(p.portid, "631");
        assert_eq!(p.protocol, "tcp");
        assert_eq!(p.service_name(), "ipp");
        assert_eq!(p.service_product(), "CUPS");
        assert_eq!(p.service_version(), "2.4");
        assert_eq!(p.service_ostype(), "NULL");
        assert_eq!(p.service_extrainfo(), "NULL");
        assert_eq!(run.host.unwrap().hostnames.hostname[0].name, "localhost");
    }

    #[test]
    fn parses_scan_without_host_element() {
        let run = parse_nmap_xml(NO_OPEN).unwrap();
        assert!(run.host.is_none());
        assert!(open_ports(&run).is_empty());
    }

    #[test]
    fn invalid_xml_is_an_error() {
        let err = parse_nmap_xml("<nmaprun><oops").unwrap_err();
        assert!(matches!(err, ScanError::Parse(_)), "{err}");
    }

    #[test]
    fn nmap_args_full_scan() {
        let resolvers = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];
        let opts = ScanOptions {
            min_rate: "",
            ports: "",
            fast_scan: false,
            resolvers: &resolvers,
        };
        let args = nmap_args("logs/1.2.3.4.xml", "1.2.3.4", &opts);
        assert_eq!(&args[..2], ["--dns-servers", "1.1.1.1,8.8.8.8"]);
        assert!(args.contains(&"-sS".to_string()));
        assert!(args.contains(&"-sV".to_string()));
        assert!(!args.contains(&"-p".to_string()));
        assert!(!args.contains(&"--min-rate".to_string()));
        assert!(!args.contains(&"--host-timeout".to_string()));
        assert_eq!(args.last().unwrap(), "1.2.3.4");
        let ox = args.iter().position(|a| a == "-oX").unwrap();
        assert_eq!(args[ox + 1], "logs/1.2.3.4.xml");
    }

    #[test]
    fn nmap_args_fast_scan_with_ports_and_rate() {
        let opts = ScanOptions {
            min_rate: "5000",
            ports: "22,80,1000-2000",
            fast_scan: true,
            resolvers: &[],
        };
        let args = nmap_args("x.xml", "1.2.3.4", &opts);
        assert!(!args.contains(&"--dns-servers".to_string()));
        assert!(!args.contains(&"-sV".to_string()));
        let rate = args.iter().position(|a| a == "--min-rate").unwrap();
        assert_eq!(args[rate + 1], "5000");
        let p = args.iter().position(|a| a == "-p").unwrap();
        assert_eq!(args[p + 1], "22,80,1000-2000");
        let ht = args.iter().position(|a| a == "--host-timeout").unwrap();
        assert_eq!(args[ht + 1], "20m");
    }

    #[test]
    fn get_nmap_data_without_nmap_in_path_is_a_spawn_error() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os("PATH");
        unsafe { std::env::set_var("PATH", "") };
        let res = get_nmap_data(
            "/nonexistent/unimap.xml",
            "127.0.0.1",
            &ScanOptions::default(),
        );
        let check = check_nmap_available();
        match old {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        assert!(matches!(res, Err(ScanError::Spawn(_))));
        assert!(matches!(check, Err(ScanError::Spawn(_))));
    }

    #[test]
    fn scan_error_display() {
        assert_eq!(
            ScanError::NoOutput("QUITTING!".into()).to_string(),
            "nmap did not produce a valid XML output: QUITTING!"
        );
        assert_eq!(
            ScanError::NoOutput(String::new()).to_string(),
            "nmap did not produce a valid XML output"
        );
    }

    #[test]
    fn stale_xml_from_a_previous_run_is_removed_before_scanning() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("1.2.3.4.xml");
        std::fs::write(&stale, FAST).unwrap();
        let old = std::env::var_os("PATH");
        unsafe { std::env::set_var("PATH", "") };
        let res = get_nmap_data(stale.to_str().unwrap(), "1.2.3.4", &ScanOptions::default());
        match old {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        assert!(res.is_err());
        assert!(!stale.exists(), "stale XML must not survive a failed scan");
    }

    #[test]
    fn failing_nmap_exit_status_is_an_error_even_if_a_file_exists() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // A fake nmap that writes a bogus file and exits 1.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let fake = dir.path().join("nmap");
            std::fs::write(
                &fake,
                "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in *.xml) echo bogus > \"$a\";; esac; done\necho 'Failed to resolve.' >&2\nexit 1\n",
            )
            .unwrap();
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
            let out = dir.path().join("out.xml");
            let old = std::env::var_os("PATH");
            unsafe { std::env::set_var("PATH", dir.path()) };
            let res = get_nmap_data(out.to_str().unwrap(), "1.2.3.4", &ScanOptions::default());
            match old {
                Some(p) => unsafe { std::env::set_var("PATH", p) },
                None => unsafe { std::env::remove_var("PATH") },
            }
            let err = res.unwrap_err();
            assert!(matches!(err, ScanError::NoOutput(_)), "{err}");
            let msg = err.to_string();
            assert!(msg.contains("exit status 1"), "{msg}");
            assert!(msg.contains("Failed to resolve."), "{msg}");
        }
    }
}
