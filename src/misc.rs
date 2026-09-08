use std::{
    collections::HashSet,
    io::{self, Read},
};

/// `https://www.example.com/path` becomes `example.com`.
#[must_use]
pub fn sanitize_target_string(target: &str) -> String {
    let target = target.trim();
    let target = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .unwrap_or(target);
    let target = target.strip_prefix("www.").unwrap_or(target);
    let target = target.split(['/', '?', '#']).next().unwrap_or(target);
    target.trim_end_matches('.').to_lowercase()
}

pub fn read_stdin() -> HashSet<String> {
    let mut buffer = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buffer) {
        log::error!("Error reading the target list from stdin: {e}");
        return HashSet::new();
    }
    normalize_targets(buffer.lines())
}

pub fn normalize_targets<'a, I>(lines: I) -> HashSet<String>
where
    I: IntoIterator<Item = &'a str>,
{
    lines
        .into_iter()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_scheme_www_and_path() {
        assert_eq!(
            sanitize_target_string("https://www.example.com/"),
            "example.com"
        );
        assert_eq!(
            sanitize_target_string("http://example.com/a/b"),
            "example.com"
        );
        assert_eq!(sanitize_target_string("www.example.com"), "example.com");
        assert_eq!(sanitize_target_string("example.com"), "example.com");
        assert_eq!(sanitize_target_string("  Example.COM  "), "example.com");
        assert_eq!(sanitize_target_string("example.com?x=1"), "example.com");
        assert_eq!(sanitize_target_string("example.com."), "example.com");
    }

    #[test]
    fn sanitize_keeps_www_in_the_middle_of_a_name() {
        assert_eq!(
            sanitize_target_string("www.www2.example.com"),
            "www2.example.com"
        );
        assert_eq!(
            sanitize_target_string("mywww.example.com"),
            "mywww.example.com"
        );
    }

    #[test]
    fn normalize_dedups_and_drops_blank_lines() {
        let set = normalize_targets(["A.com", "", "  a.com ", "b.com", "   "]);
        assert_eq!(set.len(), 2);
        assert!(set.contains("a.com"));
        assert!(set.contains("b.com"));
    }
}
