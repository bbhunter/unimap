use {crate::nmap::Port, std::net::Ipv4Addr};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ScanStatus {
    #[default]
    Scanned,
    /// The IP is not routable, so Nmap was not run.
    Skipped,
    /// Nmap failed, the ports are unknown.
    Failed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolvData {
    pub ip: Option<Ipv4Addr>,
    pub ports_data: Vec<Port>,
    pub status: ScanStatus,
}

impl ResolvData {
    #[must_use]
    pub fn ip_string(&self) -> String {
        self.ip.map_or_else(String::new, |ip| ip.to_string())
    }

    #[must_use]
    pub fn ports_column(&self) -> String {
        match self.status {
            ScanStatus::Scanned => {
                let ports: Vec<String> = self.ports_data.iter().map(|p| p.portid.clone()).collect();
                crate::logic::return_ports_string(&ports)
            }
            ScanStatus::Skipped => "NOT SCANNED".to_string(),
            ScanStatus::Failed => "SCAN FAILED".to_string(),
        }
    }
}
