use {
    clap::Parser,
    log::{Level, error, info},
    std::io::IsTerminal,
    unimap::{
        args,
        errors::{Result, bail},
        files::return_file_targets,
        logger,
        logic::validate_target,
        misc::{read_stdin, sanitize_target_string},
        resolver_engine,
    },
};

fn run() -> Result<()> {
    if std::env::var("UNIMAP_LOG_LEVEL").is_ok() {
        logger::init_by_env()?;
    } else {
        logger::init_with_level(Level::Info)?;
    }

    let mut arguments = args::Args::parse().into_processed_args();

    let raw_targets: Vec<String> = if !arguments.files.is_empty() {
        return_file_targets(&arguments.files, arguments.quiet_flag)?
    } else if !arguments.target.is_empty() {
        vec![arguments.target.clone()]
    } else if arguments.from_stdin || !std::io::stdin().is_terminal() {
        read_stdin().into_iter().collect()
    } else {
        Vec::new()
    };

    let mut invalid = 0usize;
    for target in raw_targets {
        let sanitized = sanitize_target_string(&target);
        if validate_target(&sanitized) {
            arguments.targets.insert(sanitized);
        } else {
            invalid += 1;
        }
    }

    if arguments.targets.is_empty() {
        bail!("Target is empty or invalid!");
    }
    if invalid > 0 && !arguments.quiet_flag {
        info!("Skipped {invalid} invalid targets.\n");
    }

    arguments.adjust_threads_to_targets();

    rayon::ThreadPoolBuilder::new()
        .num_threads(arguments.threads)
        .build_global()?;

    resolver_engine::parallel_resolver_all(&mut arguments)
}

fn main() {
    if let Err(err) = run() {
        error!("Error: {err}\n");
        for cause in err.chain().skip(1) {
            error!("Error description: {cause}\n");
        }
        println!();
        std::process::exit(1);
    }
}
