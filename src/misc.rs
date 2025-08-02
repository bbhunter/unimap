use std::{
    collections::HashSet,
    io::{self, Read},
};

#[must_use]
pub fn sanitize_target_string(target: String) -> String {
    target
        .replace("www.", "")
        .replace("https://", "")
        .replace("http://", "")
        .replace('/', "")
}

pub fn read_stdin() -> HashSet<String> {
    let mut buffer = String::new();
    let mut stdin = io::stdin();
    stdin
        .read_to_string(&mut buffer)
        .expect("Error getting input list.");
    buffer.lines().map(str::to_owned).collect()
}
