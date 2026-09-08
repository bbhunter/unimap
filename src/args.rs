use {
    crate::{defaults, logic::validate_target, misc::sanitize_target_string},
    chrono::Utc,
    clap::Parser,
    std::{collections::HashSet, time::Instant},
};

/// Scan only once by IP address and reduce scan times with Nmap for large amounts of data.
#[derive(Parser, Debug, Clone)]
#[command(author = "Eduard Tolosa <edu4rdshl@protonmail.com>", version, about, long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Args {
    /// Target host
    #[arg(short, long, conflicts_with_all = ["files", "stdin"])]
    pub target: Option<String>,

    /// Use a list of targets written in a file as input
    #[arg(short, long, conflicts_with_all = ["target", "stdin"])]
    pub files: Vec<String>,

    /// Write to an output file. The name of the output file will be unimap-log-date
    #[arg(short, long, conflicts_with = "unique_output")]
    pub output: bool,

    /// Write the output in CSV format to the specified filename
    #[arg(short, long, conflicts_with = "output")]
    pub unique_output: Option<String>,

    /// Remove informative messages
    #[arg(short, long)]
    pub quiet: bool,

    /// Number of threads to use to perform the resolution
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub threads: Option<u16>,

    /// Path to a file (or files) containing a list of DNS IP address. If no specified then a list of built-in DNS servers is used
    #[arg(long = "resolvers")]
    pub custom_resolvers: Vec<String>,

    /// Ports to scan. You can specify a range of ports, a list, or both. Put them inside double quotes, for example: "22, 80, 443, 1000-5000"
    #[arg(long)]
    pub ports: Option<String>,

    /// Nmap --min-rate value for ports scan
    #[arg(long)]
    pub min_rate: Option<String>,

    /// Use fast scanning for ports (no version detection)
    #[arg(long)]
    pub fast_scan: bool,

    /// Path to save the CSV data of the process and/or Nmap XML files. Default to logs/
    #[arg(long, default_value = defaults::DEFAULT_LOGS_DIR)]
    pub logs_dir: String,

    /// Delete the Nmap XML files created in the logs directory for every scanned IP. By default they are kept, that data is useful for other tasks
    #[arg(short = 'k', long)]
    pub no_keep_nmap_logs: bool,

    /// Use raw output instead of a table
    #[arg(short, long, conflicts_with = "url_output")]
    pub raw_output: bool,

    /// Use HOST:IP output format
    #[arg(long, conflicts_with = "raw_output")]
    pub url_output: bool,

    /// Read from stdin instead of files or arguments
    #[arg(long, conflicts_with_all = ["files", "target"])]
    pub stdin: bool,
}

impl Args {
    /// Create the processed args with computed fields
    #[must_use]
    pub fn into_processed_args(self) -> ProcessedArgs {
        let target = self.target.map_or_else(String::new, |target| {
            let sanitized = sanitize_target_string(&target);
            if validate_target(&sanitized) {
                sanitized
            } else {
                String::new()
            }
        });

        let file_name = if self.output {
            format!(
                "{}/unimap{}.csv",
                self.logs_dir,
                Utc::now().format("-log-%Y-%m-%d_%H-%M-%S")
            )
        } else if let Some(unique_output) = &self.unique_output {
            unique_output.clone()
        } else {
            String::new()
        };

        let threads = match (self.threads, self.ports.is_some()) {
            (Some(t), _) => usize::from(t),
            (None, true) => defaults::DEFAULT_THREADS_WITH_PORTS,
            (None, false) => defaults::DEFAULT_THREADS,
        };

        let custom_resolvers_flag = !self.custom_resolvers.is_empty();
        let custom_ports_range = self.ports.is_some();
        let ports_value = self.ports.unwrap_or_default();

        let resolvers = if custom_resolvers_flag {
            self.custom_resolvers
        } else {
            defaults::ipv4_resolvers()
        };

        ProcessedArgs {
            target,
            file_name,
            version: env!("CARGO_PKG_VERSION").to_string(),
            logs_dir: self.logs_dir,
            threads,
            ports: ports_value,
            with_output: self.output || self.unique_output.is_some(),
            unique_output_flag: self.unique_output.is_some(),
            min_rate: self.min_rate.unwrap_or_default(),
            from_file_flag: !self.files.is_empty(),
            quiet_flag: self.quiet,
            custom_resolvers: custom_resolvers_flag,
            custom_ports_range,
            no_keep_nmap_logs: self.no_keep_nmap_logs,
            raw_output: self.raw_output,
            fast_scan: self.fast_scan,
            url_output: self.url_output,
            from_stdin: self.stdin,
            files: self.files,
            resolvers,
            targets: HashSet::new(),
            time_wasted: Instant::now(),
        }
    }
}

/// Processed args with computed fields and flags
#[derive(Clone, Debug)]
pub struct ProcessedArgs {
    pub target: String,
    pub file_name: String,
    pub version: String,
    pub logs_dir: String,
    pub threads: usize,
    pub ports: String,
    pub with_output: bool,
    pub unique_output_flag: bool,
    pub min_rate: String,
    pub from_file_flag: bool,
    pub quiet_flag: bool,
    pub custom_resolvers: bool,
    pub custom_ports_range: bool,
    pub no_keep_nmap_logs: bool,
    pub raw_output: bool,
    pub fast_scan: bool,
    pub url_output: bool,
    pub from_stdin: bool,
    pub files: Vec<String>,
    /// Either the built-in resolver IPs or, when `custom_resolvers` is set, the paths of the
    /// files that contain the resolver IPs.
    pub resolvers: Vec<String>,
    pub targets: HashSet<String>,
    pub time_wasted: Instant,
}

impl ProcessedArgs {
    pub fn adjust_threads_to_targets(&mut self) {
        if self.targets.len() < defaults::THREADS_TARGETS_THRESHOLD {
            self.threads = self.targets.len().max(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> ProcessedArgs {
        Args::try_parse_from(std::iter::once("unimap").chain(argv.iter().copied()))
            .expect("args should parse")
            .into_processed_args()
    }

    #[test]
    fn target_is_sanitized_and_validated() {
        assert_eq!(
            parse(&["-t", "https://www.Example.com/"]).target,
            "example.com"
        );
        assert_eq!(parse(&["-t", "not a host"]).target, "");
        assert_eq!(parse(&["-t", "localhost"]).target, "");
    }

    #[test]
    fn thread_defaults() {
        assert_eq!(parse(&["-t", "a.com"]).threads, defaults::DEFAULT_THREADS);
        assert_eq!(
            parse(&["-t", "a.com", "--ports", "80"]).threads,
            defaults::DEFAULT_THREADS_WITH_PORTS
        );
        assert_eq!(parse(&["-t", "a.com", "--threads", "7"]).threads, 7);
        assert_eq!(
            parse(&["-t", "a.com", "--ports", "80", "--threads", "7"]).threads,
            7
        );
    }

    #[test]
    fn zero_threads_is_rejected() {
        assert!(Args::try_parse_from(["unimap", "-t", "a.com", "--threads", "0"]).is_err());
    }

    #[test]
    fn adjust_threads_to_small_target_lists() {
        let mut args = parse(&["-t", "a.com", "--threads", "40"]);
        args.targets = ["a.com", "b.com", "c.com"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        args.adjust_threads_to_targets();
        assert_eq!(args.threads, 3);

        let mut args = parse(&["-t", "a.com", "--threads", "40"]);
        args.targets = (0..defaults::THREADS_TARGETS_THRESHOLD)
            .map(|i| format!("h{i}.com"))
            .collect();
        args.adjust_threads_to_targets();
        assert_eq!(args.threads, 40);

        let mut args = parse(&["-t", "a.com"]);
        args.adjust_threads_to_targets();
        assert_eq!(args.threads, 1, "never build a pool with zero threads");
    }

    #[test]
    fn output_file_names() {
        let a = parse(&["-t", "a.com", "-o"]);
        assert!(a.with_output);
        assert!(!a.unique_output_flag);
        assert!(a.file_name.starts_with("unimap_logs/unimap-log-"));
        assert!(a.file_name.ends_with(".csv"));

        let a = parse(&["-t", "a.com", "-o", "--logs-dir", "/tmp/x"]);
        assert!(a.file_name.starts_with("/tmp/x/unimap-log-"));

        let a = parse(&["-t", "a.com", "-u", "out.csv"]);
        assert!(a.with_output);
        assert!(a.unique_output_flag);
        assert_eq!(a.file_name, "out.csv");

        let a = parse(&["-t", "a.com"]);
        assert!(!a.with_output);
        assert_eq!(a.file_name, "");
    }

    #[test]
    fn resolvers_default_and_custom() {
        let a = parse(&["-t", "a.com"]);
        assert!(!a.custom_resolvers);
        assert_eq!(a.resolvers, defaults::ipv4_resolvers());

        let a = parse(&[
            "-t",
            "a.com",
            "--resolvers",
            "r1.txt",
            "--resolvers",
            "r2.txt",
        ]);
        assert!(a.custom_resolvers);
        assert_eq!(a.resolvers, vec!["r1.txt", "r2.txt"]);
    }

    #[test]
    fn conflicting_inputs_are_rejected() {
        assert!(Args::try_parse_from(["unimap", "-t", "a.com", "-f", "x.txt"]).is_err());
        assert!(Args::try_parse_from(["unimap", "-t", "a.com", "--stdin"]).is_err());
        assert!(Args::try_parse_from(["unimap", "-f", "x.txt", "--stdin"]).is_err());
        assert!(Args::try_parse_from(["unimap", "-t", "a.com", "-o", "-u", "x.csv"]).is_err());
        assert!(Args::try_parse_from(["unimap", "-t", "a.com", "-r", "--url-output"]).is_err());
    }
}
