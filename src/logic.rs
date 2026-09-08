const SPECIAL_CHARS: &[char] = &[
    '[', ']', '{', '}', '(', ')', '*', '|', ':', '<', '>', '/', '\\', '%', '&', '¿', '?', '¡', '!',
    '#', '\'', ' ', ',',
];

#[must_use]
pub fn validate_target(target: &str) -> bool {
    !target.is_empty()
        && !target.starts_with('.')
        && !target.ends_with('.')
        && target.contains('.')
        && !target.contains(SPECIAL_CHARS)
        && target.is_ascii()
}

#[must_use]
pub fn null_ip_checker(ip: &str) -> String {
    if ip.is_empty() {
        String::from("NULL")
    } else {
        ip.to_string()
    }
}

#[must_use]
pub fn return_ports_string(ports: &[String]) -> String {
    if ports.is_empty() {
        String::from("NULL")
    } else {
        ports.join(";")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_targets() {
        for t in [
            "example.com",
            "sub.example.com",
            "a-b.example.co.uk",
            "xn--bcher-kva.example",
            "1.2.3.4",
            "under_score.example.com",
        ] {
            assert!(validate_target(t), "{t} should be valid");
        }
    }

    #[test]
    fn invalid_targets() {
        for t in [
            "",
            "localhost",
            ".example.com",
            "example.com.",
            "exam ple.com",
            "example.com/path",
            "http://example.com",
            "example.com:80",
            "a,b.com",
            "ejemplo.ñandu.com",
            "*.example.com",
            "example.com?x=1",
            "example.com#frag",
            "it's.example.com",
        ] {
            assert!(!validate_target(t), "{t} should be invalid");
        }
    }

    #[test]
    fn null_ip() {
        assert_eq!(null_ip_checker(""), "NULL");
        assert_eq!(null_ip_checker("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn ports_string() {
        assert_eq!(return_ports_string(&[]), "NULL");
        assert_eq!(return_ports_string(&["22".to_string()]), "22");
        assert_eq!(
            return_ports_string(&["22".to_string(), "80".to_string(), "443".to_string()]),
            "22;80;443"
        );
    }
}
