use chrono::Local;
#[cfg(feature = "colored")]
use colored::Colorize;
use log::{Level, Log, Metadata, Record, SetLoggerError};

struct SimpleLogger {
    level: Level,
}

impl Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        let target = if record.target().is_empty() {
            record.module_path().unwrap_or_default()
        } else {
            record.target()
        };
        if target.contains("unimap") && self.enabled(record.metadata()) {
            let level_string = {
                #[cfg(feature = "colored")]
                {
                    match record.level() {
                        Level::Error => record.level().to_string().red(),
                        Level::Warn => record.level().to_string().yellow(),
                        Level::Info => record.level().to_string().cyan(),
                        Level::Debug => record.level().to_string().purple(),
                        Level::Trace => record.level().to_string().normal(),
                    }
                }
                #[cfg(not(feature = "colored"))]
                {
                    record.level().to_string()
                }
            };
            print!(
                "\n{} [{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S,%3f"),
                level_string,
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

pub fn init_with_level(level: Level) -> Result<(), SetLoggerError> {
    #[cfg(all(windows, feature = "colored"))]
    {
        use std::io::IsTerminal;
        if std::io::stdout().is_terminal() {
            let _ = colored::control::set_virtual_terminal(true);
        }
    }

    let logger = SimpleLogger { level };
    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(level.to_level_filter());
    Ok(())
}

pub fn init() -> Result<(), SetLoggerError> {
    init_with_level(Level::Trace)
}

/// Maps the `UNIMAP_LOG_LEVEL` environment variable value to a log level.
/// Unknown or missing values fall back to `Error`.
#[must_use]
pub fn level_from_env_value(value: Option<&str>) -> Level {
    match value.map(str::to_lowercase).as_deref() {
        Some("trace") => Level::Trace,
        Some("debug") => Level::Debug,
        Some("info") => Level::Info,
        Some("warn") => Level::Warn,
        _ => Level::Error,
    }
}

pub fn init_by_env() -> Result<(), SetLoggerError> {
    let value = std::env::var("UNIMAP_LOG_LEVEL").ok();
    init_with_level(level_from_env_value(value.as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_levels() {
        assert_eq!(level_from_env_value(Some("TRACE")), Level::Trace);
        assert_eq!(level_from_env_value(Some("debug")), Level::Debug);
        assert_eq!(level_from_env_value(Some("Info")), Level::Info);
        assert_eq!(level_from_env_value(Some("warn")), Level::Warn);
        assert_eq!(level_from_env_value(Some("error")), Level::Error);
        assert_eq!(level_from_env_value(Some("bogus")), Level::Error);
        assert_eq!(level_from_env_value(None), Level::Error);
    }
}
