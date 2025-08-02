use crate::nmap::Port;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ResolvData {
    pub ip: String,
    pub ports_data: Vec<Port>,
}
impl ResolvData {
    pub const fn default() -> Self {
        Self {
            ip: String::new(),
            ports_data: Vec::new(),
        }
    }
}
