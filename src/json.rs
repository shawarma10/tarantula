use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonPacket {
    pub protocol: String,
    pub length: u32,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl JsonPacket {
    pub fn new(
        protocol: impl Into<String>,
        length: u32,
        src_ip: Option<String>,
        dst_ip: Option<String>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) -> Self {
        Self {
            protocol: protocol.into(),
            length,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }
}
