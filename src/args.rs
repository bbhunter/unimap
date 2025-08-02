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
    #[arg(long)]
    pub threads: Option<usize>,

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
    #[arg(long, default_value = "unimap_logs")]
    pub logs_dir: String,

    /// Keep Nmap XML files created in the logs/ folder for every scanned IP. This data will be useful for other tasks
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
            let sanitized = sanitize_target_string(target);
            if validate_target(&sanitized) {
                sanitized
            } else {
                String::new()
            }
        });

        let file_name = if self.output {
            format!(
                "{}/unimap{}",
                self.logs_dir,
                Utc::now().format("-log-%Y-%m-%d_%H-%M-%S")
            ) + ".csv"
        } else if let Some(unique_output) = &self.unique_output {
            unique_output.clone()
        } else {
            String::new()
        };

        let threads = if self.ports.is_some() && self.threads.is_none() {
            30
        } else {
            self.threads.unwrap_or(50)
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
    pub resolvers: Vec<String>,
    pub targets: HashSet<String>,
    pub time_wasted: Instant,
}
