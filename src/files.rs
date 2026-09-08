use {
    crate::{
        errors::{Context, Result, bail},
        misc::normalize_targets,
    },
    log::{error, warn},
    prettytable::Table,
    std::{
        collections::HashSet,
        fs::{self, File, OpenOptions},
        io::{BufRead, BufReader, Write},
        path::Path,
    },
};

/// A file that cannot be opened is skipped as long as another one could be read.
pub fn return_file_targets(files: &[String], quiet: bool) -> Result<Vec<String>> {
    let mut files = files.to_vec();
    files.sort();
    files.dedup();

    let mut targets: HashSet<String> = HashSet::new();
    let mut opened = 0usize;
    let mut last_error = None;

    for f in &files {
        match File::open(f) {
            Ok(file) => {
                opened += 1;
                let lines: Vec<String> = BufReader::new(file)
                    .lines()
                    .map_while(std::result::Result::ok)
                    .collect();
                targets.extend(normalize_targets(lines.iter().map(String::as_str)));
            }
            Err(e) => {
                if !quiet && files.len() > 1 {
                    warn!("Can not open file {f}, working with next file. Error: {e}\n");
                }
                last_error = Some(e);
            }
        }
    }

    if opened == 0 {
        match (files.first(), last_error) {
            (Some(f), Some(e)) => bail!("Can not open file {f}. Error: {e}"),
            _ => bail!("No input files were given"),
        }
    }

    let mut targets: Vec<String> = targets.into_iter().collect();
    targets.sort();
    Ok(targets)
}

/// The header row is only written when the file is empty, so several runs appending to
/// the same file with `-u` produce a single valid CSV.
pub fn table_to_file(table: &Table, file: File) -> Result<()> {
    let already_has_content = file.metadata().map(|m| m.len() > 0).unwrap_or(false);
    if already_has_content {
        let mut rows_only = table.clone();
        rows_only.unset_titles();
        rows_only.to_csv(file)?;
    } else {
        table.to_csv(file)?;
    }
    Ok(())
}

pub fn return_output_file(file_name: &str) -> Result<File> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(file_name)
        .with_context(|| format!("Can't create file {file_name}"))
}

#[must_use]
pub fn check_full_path(full_path: &str) -> bool {
    Path::new(full_path).is_dir() || fs::create_dir_all(full_path).is_ok()
}

pub fn delete_files<S: ::std::hash::BuildHasher>(paths: &HashSet<String, S>) {
    for file in paths {
        if Path::new(&file).exists() {
            match std::fs::remove_file(file) {
                Ok(()) => (),
                Err(e) => error!("Error deleting the file {file}. Description: {e}"),
            }
        }
    }
}

pub fn string_to_file(data: &str, mut file: File) -> Result<()> {
    file.write_all(data.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(dir: &tempfile::TempDir, name: &str, content: &str) -> String {
        let path = dir.path().join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn reads_sorts_dedups_and_lowercases() {
        let dir = tempfile::tempdir().unwrap();
        let a = write_tmp(&dir, "a.txt", "B.com\na.com\n\n  a.com  \n");
        let b = write_tmp(&dir, "b.txt", "c.com\nA.COM\n");
        let targets = return_file_targets(&[a.clone(), b, a], true).unwrap();
        assert_eq!(targets, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn missing_single_file_is_an_error() {
        let err = return_file_targets(&["/nonexistent/unimap-x.txt".to_string()], true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Can not open file"), "{err}");
    }

    #[test]
    fn missing_file_is_skipped_when_another_one_works() {
        let dir = tempfile::tempdir().unwrap();
        let a = write_tmp(&dir, "a.txt", "a.com\n");
        let targets =
            return_file_targets(&[a, "/nonexistent/unimap-x.txt".to_string()], true).unwrap();
        assert_eq!(targets, vec!["a.com"]);
    }

    #[test]
    fn empty_file_list_is_an_error() {
        assert!(return_file_targets(&[], true).is_err());
    }

    #[test]
    fn check_full_path_creates_directories() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        let nested = nested.to_string_lossy().into_owned();
        assert!(check_full_path(&nested));
        assert!(Path::new(&nested).is_dir());
        assert!(check_full_path(&nested), "existing dir is accepted");
    }

    #[test]
    fn check_full_path_rejects_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_tmp(&dir, "f.txt", "x");
        assert!(!check_full_path(&file));
    }

    #[test]
    fn output_file_append_and_csv() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.csv").to_string_lossy().into_owned();
        let mut table = Table::new();
        table.set_titles(prettytable::row!["HOST", "IP"]);
        table.add_row(prettytable::row!["a.com", "1.2.3.4"]);
        table_to_file(&table, return_output_file(&path).unwrap()).unwrap();
        table_to_file(&table, return_output_file(&path).unwrap()).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches("a.com,1.2.3.4").count(), 2, "{content}");
        assert_eq!(
            content.matches("HOST,IP").count(),
            1,
            "header written once: {content}"
        );
        assert!(content.starts_with("HOST,IP\n"), "{content}");
    }

    #[test]
    fn delete_files_ignores_missing() {
        let dir = tempfile::tempdir().unwrap();
        let present = write_tmp(&dir, "p.txt", "x");
        let paths: HashSet<String> = [present.clone(), "/nonexistent/unimap-y".to_string()]
            .into_iter()
            .collect();
        delete_files(&paths);
        assert!(!Path::new(&present).exists());
    }
}
