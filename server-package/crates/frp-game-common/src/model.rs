use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{API_PORT, FRPS_PORT};

#[derive(Debug, Error)]
pub enum FrpGameError {
    #[error("请填写服务器IP。")]
    EmptyServer,
    #[error("服务器IP格式不正确。")]
    InvalidServer,
    #[error("协议只能选择 TCP 或 UDP。")]
    InvalidProtocol,
    #[error("请完整填写所有字段。")]
    MissingTunnelField,
    #[error("隧道信息不能包含控制字符。")]
    ControlCharacter,
    #[error("隧道名、备注或本地地址过长。")]
    TunnelFieldTooLong,
    #[error("端口必须是 1-65535 的数字。")]
    InvalidPort,
    #[error("隧道名已存在：{0}")]
    DuplicateName(String),
    #[error("{0} 远程端口已存在：{1}")]
    DuplicateRemotePort(String, u16),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tunnel {
    pub id: String,
    pub proxy_name: String,
    pub protocol: String,
    pub name: String,
    pub remark: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
    #[serde(default)]
    pub backend_port: u16,
}

impl Default for Tunnel {
    fn default() -> Self {
        let id = new_tunnel_id();
        Self {
            proxy_name: proxy_name_for(&id),
            id,
            protocol: "TCP".to_string(),
            name: String::new(),
            remark: String::new(),
            local_ip: "127.0.0.1".to_string(),
            local_port: 25565,
            remote_port: 25565,
            backend_port: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortTrafficUsage {
    pub proxy_name: String,
    pub protocol: String,
    pub remote_port: u16,
    pub traffic_in_bytes: u64,
    pub traffic_out_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrafficSummary {
    pub limit_bytes: u64,
    pub used_bytes: u64,
    pub remaining_bytes: u64,
    pub speed_limit_mbps: u32,
    pub exhausted: bool,
    #[serde(default)]
    pub ports: Vec<PortTrafficUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerProfile {
    pub id: String,
    pub label: String,
    pub server_ip: String,
    pub server_host: String,
    pub account: String,
    pub password: String,
    pub key: String,
    pub api_port: u16,
    pub api_salt: String,
    pub frps_port: u16,
    pub frps_token: String,
    #[serde(default)]
    pub frps_version: String,
    #[serde(default)]
    pub frps_online: bool,
    #[serde(default)]
    pub traffic: TrafficSummary,
    pub tunnels: Vec<Tunnel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloResponse {
    pub ok: bool,
    pub version: u8,
    pub salt: String,
    pub api_port: u16,
    pub frps_port: u16,
    #[serde(default)]
    pub frps_version: String,
    #[serde(default)]
    pub frps_online: bool,
    pub server_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub ok: bool,
    pub frps_port: u16,
    pub frps_token: String,
    #[serde(default)]
    pub frps_version: String,
    #[serde(default)]
    pub traffic: TrafficSummary,
    pub tunnels: Vec<Tunnel>,
    pub server_time: i64,
}

pub fn new_server_id() -> String {
    Uuid::new_v4().simple().to_string()[..12].to_string()
}

pub fn new_tunnel_id() -> String {
    Uuid::new_v4().simple().to_string()[..12].to_string()
}

pub fn proxy_name_for(tunnel_id: &str) -> String {
    let cleaned: String = tunnel_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    if cleaned.is_empty() {
        format!("fg-{}", new_tunnel_id())
    } else {
        format!("fg-{cleaned}")
    }
}

pub fn is_valid_port(value: u16) -> bool {
    value > 0
}

pub fn parse_frp_version_text(text: &str) -> Option<String> {
    text.split_whitespace()
        .filter_map(|part| {
            let token = part
                .trim_matches(|ch: char| {
                    !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_')
                })
                .trim_start_matches(['v', 'V']);
            let mut parts = token.split('.');
            let major = parts.next()?;
            let minor = parts.next()?;
            let patch = parts.next()?;
            let patch_core = patch.split(['-', '_']).next().unwrap_or_default();
            if major.chars().all(|ch| ch.is_ascii_digit())
                && minor.chars().all(|ch| ch.is_ascii_digit())
                && !patch_core.is_empty()
                && patch_core.chars().all(|ch| ch.is_ascii_digit())
            {
                Some(token.to_string())
            } else {
                None
            }
        })
        .next()
}

pub fn normalize_server(value: &str) -> Result<(String, String, u16, String), FrpGameError> {
    let raw = value.trim();
    if raw.is_empty() {
        return Err(FrpGameError::EmptyServer);
    }
    let url = if raw.contains("://") {
        Url::parse(raw).map_err(|_| FrpGameError::InvalidServer)?
    } else {
        Url::parse(&format!("http://{raw}")).map_err(|_| FrpGameError::InvalidServer)?
    };
    let host = url
        .host_str()
        .ok_or(FrpGameError::InvalidServer)?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = url.port().unwrap_or(API_PORT);
    let formatted_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let display = if port == API_PORT {
        formatted_host.clone()
    } else {
        format!("{formatted_host}:{port}")
    };
    Ok((
        display,
        host,
        port,
        format!("http://{formatted_host}:{port}"),
    ))
}

pub fn normalize_tunnels(tunnels: &[Tunnel]) -> Result<Vec<Tunnel>, FrpGameError> {
    let mut normalized = Vec::with_capacity(tunnels.len());
    let mut names = HashSet::new();
    let mut remote_ports = HashSet::new();

    for tunnel in tunnels {
        let mut item = tunnel.clone();
        item.protocol = item.protocol.trim().to_ascii_uppercase();
        item.name = item.name.trim().to_string();
        item.remark = item.remark.trim().to_string();
        item.local_ip = item.local_ip.trim().to_string();

        if item.id.trim().is_empty() {
            item.id = new_tunnel_id();
        }
        if item.proxy_name.trim().is_empty() {
            item.proxy_name = proxy_name_for(&item.id);
        }
        if item.protocol != "TCP" && item.protocol != "UDP" {
            return Err(FrpGameError::InvalidProtocol);
        }
        if item.name.is_empty() || item.remark.is_empty() || item.local_ip.is_empty() {
            return Err(FrpGameError::MissingTunnelField);
        }
        if item.name.chars().count() > 64
            || item.remark.chars().count() > 256
            || item.local_ip.chars().count() > 255
        {
            return Err(FrpGameError::TunnelFieldTooLong);
        }
        if item
            .name
            .chars()
            .chain(item.remark.chars())
            .chain(item.local_ip.chars())
            .any(|ch| ch < ' ')
        {
            return Err(FrpGameError::ControlCharacter);
        }
        if !is_valid_port(item.local_port) || !is_valid_port(item.remote_port) {
            return Err(FrpGameError::InvalidPort);
        }
        if !names.insert(item.name.clone()) {
            return Err(FrpGameError::DuplicateName(item.name));
        }
        let remote_key = (item.protocol.clone(), item.remote_port);
        if !remote_ports.insert(remote_key.clone()) {
            return Err(FrpGameError::DuplicateRemotePort(
                remote_key.0,
                remote_key.1,
            ));
        }
        normalized.push(item);
    }

    Ok(normalized)
}

impl ServerProfile {
    pub fn new_empty() -> Self {
        Self {
            id: new_server_id(),
            api_port: API_PORT,
            frps_port: FRPS_PORT,
            ..Self::default()
        }
    }

    pub fn title(&self) -> String {
        if !self.label.trim().is_empty() {
            self.label.clone()
        } else if !self.server_ip.trim().is_empty() {
            self.server_ip.clone()
        } else {
            "未命名服务器".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ipv6_api_urls_with_brackets() {
        let (display, host, port, base) = normalize_server("[::1]:8000").unwrap();
        assert_eq!(display, "[::1]:8000");
        assert_eq!(host, "::1");
        assert_eq!(port, 8000);
        assert_eq!(base, "http://[::1]:8000");
    }
}
