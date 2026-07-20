use anyhow::{bail, Context, Result};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::{Parser, Subcommand};
use frp_game_common::{
    decrypt_payload, encrypt_payload, normalize_tunnels, parse_frp_version_text, proxy_name_for,
    Envelope, PortTrafficUsage, TrafficSummary, Tunnel, API_PORT, FRPS_PORT, MAX_TUNNEL_LIMIT,
};
use rand::seq::SliceRandom;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng, RngCore};
use semver::Version;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use crate::controller::{spawn_accounting_task, TrafficController};
use crate::storage::{
    allocate_backend_port, decrypt_user_password, encrypt_user_password, hash_password,
    new_user_id, verify_password, ProxyTrafficRecord, ServerConfig, ServerUser, Storage,
    DEFAULT_PLUGIN_PORT, DEFAULT_PUBLIC_BIND, MAX_TUNNELS_PER_USER,
};

const SERVICE_NAME: &str = "frp-game";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const SERVER_UPDATE_MANIFEST_URL: &str =
    "https://raw.githubusercontent.com/juzihensuan/Orange-FRP/main/server-package/update.json";
const SERVER_UPDATE_INSTALLER_URL: &str =
    "https://raw.githubusercontent.com/juzihensuan/Orange-FRP/main/install-server.sh";
const DEFAULT_API_BIND: &str = "0.0.0.0";
const ORANGE_FRPS_VERSION: &str = "0.69.1";
const ORANGE_FRPS_DOWNLOAD_URL: &str = "https://raw.githubusercontent.com/juzihensuan/Orange-FRP/2fce759440a07f2b98a233faac947b82e6f40de4/Update/frps0.69.1";
const ORANGE_FRPS_SHA256: &str = "68d2908bb73fe7a03c29d9227d2acc2104bff3fea6b1cece0b8388c1a0660442";
const FRPS_INSTALL_PATH: &str = "/usr/local/bin/frps";
const SERVER_INSTALL_PATH: &str = "/usr/local/bin/frp-game-server";
const ORANGE_MENU_PATH: &str = "/usr/local/bin/orange";
const LOG_DIR: &str = "/var/log/frp-game";
const FRPS_OWNED_MARKER: &str = ".orange-frps-owned";
const API_BODY_LIMIT_BYTES: usize = 256 * 1024;
const MAX_REPLAY_ENTRIES: usize = 16_384;
const MAX_RATE_LIMIT_CLIENTS: usize = 8_192;
const REPLAY_TTL: Duration = Duration::from_secs(300);
const RATE_LIMIT_IDLE_TTL: Duration = Duration::from_secs(300);
const RATE_LIMIT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_NEW_USER_TUNNEL_LIMIT: u32 = 5;
const UPDATE_MANIFEST_MAX_BYTES: usize = 4 * 1024;
const UPDATE_INSTALLER_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "frp-game-server",
    version,
    about = "Orange FRP Linux 服务端管理工具"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Init {
        #[arg(long, default_value = DEFAULT_API_BIND)]
        api_bind: String,
        #[arg(long, default_value_t = API_PORT)]
        api_port: u16,
        #[arg(long, default_value_t = FRPS_PORT)]
        frps_port: u16,
        #[arg(long, default_value = "frps")]
        frps_binary: String,
    },
    Setup {
        #[arg(long, default_value = DEFAULT_API_BIND)]
        api_bind: String,
        #[arg(long, default_value_t = API_PORT)]
        api_port: u16,
        #[arg(long, default_value_t = FRPS_PORT)]
        frps_port: u16,
        #[arg(long, default_value = FRPS_INSTALL_PATH)]
        frps_binary: String,
        #[arg(long)]
        skip_frps_install: bool,
        #[arg(long)]
        force_frps: bool,
    },
    Show,
    Menu,
    AddUser {
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        traffic_limit_gb: Option<f64>,
        #[arg(long)]
        speed_limit_mbps: Option<u32>,
        #[arg(long)]
        tunnel_limit: Option<u32>,
    },
    ViewUsers,
    DeleteUser,
    ViewTraffic {
        #[arg(long)]
        account: Option<String>,
    },
    SetTrafficLimit {
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        gb: Option<f64>,
    },
    SetTrafficUsed {
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        gb: Option<f64>,
    },
    SetSpeedLimit {
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        mbps: Option<u32>,
    },
    SetTunnelLimit {
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
    },
    CheckUpdate {
        #[arg(short, long)]
        yes: bool,
    },
    Serve {
        #[arg(long)]
        api_only: bool,
    },
    InstallService,
    InstallFrps {
        #[arg(long)]
        force: bool,
    },
    ChangeAccount,
    ChangePassword,
    RotateKey {
        #[arg(short, long)]
        yes: bool,
    },
    Uninstall {
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Debug, Deserialize)]
struct ServerUpdateManifest {
    version: String,
    installer_sha256: String,
}

#[derive(Clone)]
struct ApiState {
    config: Arc<RwLock<ServerConfig>>,
    storage: Storage,
    controller: Option<TrafficController>,
    frps_version: String,
    frps_online: Arc<AtomicBool>,
    replay: Arc<Mutex<ReplayGuard>>,
    rate_limit: Arc<Mutex<ApiRateLimiter>>,
}

#[derive(Default)]
struct ReplayGuard {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<(Instant, [u8; 32])>,
}

impl ReplayGuard {
    fn accept(&mut self, user_id: &str, operation: &str, nonce: &str) -> bool {
        let now = Instant::now();
        while let Some((seen_at, key)) = self.order.front().copied() {
            if now.duration_since(seen_at) <= REPLAY_TTL {
                break;
            }
            self.order.pop_front();
            self.seen.remove(&key);
        }

        let mut digest = Sha256::new();
        for field in [user_id, operation, nonce] {
            digest.update((field.len() as u64).to_le_bytes());
            digest.update(field.as_bytes());
        }
        let key: [u8; 32] = digest.finalize().into();
        if !self.seen.insert(key) {
            return false;
        }
        if self.seen.len() > MAX_REPLAY_ENTRIES {
            if let Some((_, oldest)) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.order.push_back((now, key));
        true
    }
}

#[derive(Default)]
struct ApiRateLimiter {
    clients: HashMap<IpAddr, RateBucket>,
    last_cleanup: Option<Instant>,
}

struct RateBucket {
    tokens: f64,
    updated: Instant,
}

impl ApiRateLimiter {
    fn allow(&mut self, ip: IpAddr, cost: f64) -> bool {
        const CAPACITY: f64 = 60.0;
        const REFILL_PER_SECOND: f64 = 2.0;
        let now = Instant::now();
        if self
            .last_cleanup
            .map(|last| now.duration_since(last) >= RATE_LIMIT_CLEANUP_INTERVAL)
            .unwrap_or(true)
        {
            self.clients
                .retain(|_, bucket| now.duration_since(bucket.updated) < RATE_LIMIT_IDLE_TTL);
            self.last_cleanup = Some(now);
        }
        if !self.clients.contains_key(&ip) && self.clients.len() >= MAX_RATE_LIMIT_CLIENTS {
            return false;
        }
        let bucket = self.clients.entry(ip).or_insert(RateBucket {
            tokens: CAPACITY,
            updated: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * REFILL_PER_SECOND).min(CAPACITY);
        bucket.updated = now;
        if bucket.tokens < cost {
            return false;
        }
        bucket.tokens -= cost;
        true
    }
}

struct AuthContext {
    user_index: usize,
    payload: Value,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn config_dir() -> PathBuf {
    env::var_os("FRP_GAME_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/frp-game"))
}

fn database_file() -> PathBuf {
    config_dir().join("orange-frp.db")
}

fn storage() -> Storage {
    Storage::new(database_file())
}

fn frps_config_file() -> PathBuf {
    config_dir().join("frps.toml")
}

fn frps_owned_marker() -> PathBuf {
    config_dir().join(FRPS_OWNED_MARKER)
}

fn atomic_write_file(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    #[cfg(not(unix))]
    let _ = mode;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("orange-frp");
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        }
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn systemd_unit() -> PathBuf {
    env::var_os("FRP_GAME_SYSTEMD_UNIT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/etc/systemd/system/{SERVICE_NAME}.service")))
}

fn require_root(action: &str) -> Result<()> {
    #[cfg(not(unix))]
    let _ = action;
    #[cfg(unix)]
    if unsafe { libc_geteuid() } != 0 {
        bail!("{action} 需要 root 权限，请使用 sudo 运行。");
    }
    Ok(())
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

fn random_secret(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut chars = vec![
        rng.gen_range(b'a'..=b'z') as char,
        rng.gen_range(b'A'..=b'Z') as char,
        rng.gen_range(b'0'..=b'9') as char,
    ];
    chars.extend((chars.len()..length).map(|_| rng.sample(Alphanumeric) as char));
    chars.shuffle(&mut rng);
    chars.into_iter().collect()
}

fn random_token(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn random_salt() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn new_config(
    api_bind: String,
    api_port: u16,
    frps_port: u16,
    frps_binary: String,
) -> ServerConfig {
    let now = now_unix();
    ServerConfig {
        revision: 0,
        api_salt: random_salt(),
        api_bind,
        api_port,
        frps_bind_port: frps_port,
        frps_token: random_token(48),
        frps_binary,
        plugin_port: DEFAULT_PLUGIN_PORT,
        public_bind: DEFAULT_PUBLIC_BIND.to_string(),
        users: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

fn color(text: impl AsRef<str>, code: &str) -> String {
    format!("\x1b[{code}m{}\x1b[0m", text.as_ref())
}

fn print_title() {
    println!(
        "{}",
        color("======================================", "95;1")
    );
    println!("{}", color("          Orange FRP 菜单栏", "95;1"));
    println!(
        "{}",
        color(format!("          服务端版本 v{SERVER_VERSION}"), "90;1")
    );
    println!(
        "{}",
        color("======================================", "95;1")
    );
}

fn prompt_non_empty(label: &str) -> Result<String> {
    loop {
        print!("{label}");
        io::stdout().flush()?;
        let mut value = String::new();
        if io::stdin().read_line(&mut value)? == 0 {
            bail!("输入已结束。");
        }
        let value = value.trim().to_string();
        if !value.is_empty() {
            return Ok(value);
        }
        println!("不能为空，请重新输入。");
    }
}

fn prompt_password(confirm: bool) -> Result<String> {
    loop {
        let password = rpassword::prompt_password("请输入密码: ")?;
        if password.is_empty() {
            println!("密码不能为空，请重新输入。");
            continue;
        }
        if confirm {
            let repeated = rpassword::prompt_password("请再次输入密码: ")?;
            if password != repeated {
                println!("两次输入的密码不一致，请重新输入。");
                continue;
            }
        }
        return Ok(password);
    }
}

fn prompt_f64(label: &str, default: f64) -> Result<f64> {
    loop {
        print!("{label}");
        io::stdout().flush()?;
        let mut value = String::new();
        if io::stdin().read_line(&mut value)? == 0 {
            bail!("输入已结束。");
        }
        let value = value.trim();
        if value.is_empty() {
            return Ok(default);
        }
        match value.parse::<f64>() {
            Ok(number) if number.is_finite() && number >= 0.0 => return Ok(number),
            _ => println!("请输入大于等于 0 的数字。"),
        }
    }
}

fn prompt_u32(label: &str, default: u32) -> Result<u32> {
    loop {
        print!("{label}");
        io::stdout().flush()?;
        let mut value = String::new();
        if io::stdin().read_line(&mut value)? == 0 {
            bail!("输入已结束。");
        }
        let value = value.trim();
        if value.is_empty() {
            return Ok(default);
        }
        match value.parse::<u32>() {
            Ok(number) => return Ok(number),
            Err(_) => println!("请输入大于等于 0 的整数。"),
        }
    }
}

fn gb_to_bytes(gb: f64) -> Result<u64> {
    if !gb.is_finite() || gb < 0.0 {
        bail!("流量必须是大于等于 0 的数字。");
    }
    let bytes = gb * 1024.0 * 1024.0 * 1024.0;
    if bytes > i64::MAX as f64 {
        bail!("流量数值过大。");
    }
    Ok(bytes.round() as u64)
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.2} GB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.2} MB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.2} KB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

fn detect_primary_ip() -> String {
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("1.1.1.1:80").is_ok() {
            if let Ok(address) = socket.local_addr() {
                return address.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

fn detect_public_ip() -> String {
    let result = reqwest::blocking::Client::builder()
        .user_agent("orange-frp-server")
        .timeout(Duration::from_secs(5))
        .build()
        .and_then(|client| client.get("https://api.ipify.org").send())
        .and_then(|response| response.error_for_status())
        .and_then(|response| response.text())
        .map(|text| text.trim().to_string());
    match result {
        Ok(text) if !text.is_empty() => text,
        _ => detect_primary_ip(),
    }
}

fn update_http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(format!("orange-frp-server/{SERVER_VERSION}"))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()
        .context("无法创建服务端更新客户端")
}

fn fetch_update_bytes(
    client: &reqwest::blocking::Client,
    url: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let cache_busted_url = format!("{url}?t={}", now_unix());
    let response = client
        .get(cache_busted_url)
        .header("Cache-Control", "no-cache")
        .send()
        .with_context(|| format!("无法下载{label}"))?
        .error_for_status()
        .with_context(|| format!("下载{label}失败"))?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        bail!("{label}超过允许大小，已拒绝处理。");
    }
    let mut bytes = Vec::with_capacity(maximum_bytes.min(16 * 1024));
    response
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("读取{label}失败"))?;
    if bytes.len() > maximum_bytes {
        bail!("{label}超过允许大小，已拒绝处理。");
    }
    Ok(bytes)
}

fn parse_server_update_manifest(bytes: &[u8]) -> Result<(Version, String)> {
    let manifest: ServerUpdateManifest =
        serde_json::from_slice(bytes).context("服务端更新清单格式不正确")?;
    let version_text = manifest.version.trim().trim_start_matches(['v', 'V']);
    let version = Version::parse(version_text).context("服务端更新版本号格式不正确")?;
    let installer_sha256 = manifest.installer_sha256.trim().to_ascii_lowercase();
    if installer_sha256.len() != 64
        || !installer_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("服务端更新清单中的安装脚本 SHA-256 不正确。");
    }
    Ok((version, installer_sha256))
}

fn parse_server_version_output(output: &[u8]) -> Result<Version> {
    let text = String::from_utf8_lossy(output);
    text.split_whitespace()
        .find_map(|part| Version::parse(part.trim_start_matches(['v', 'V'])).ok())
        .context("无法从服务端版本输出中读取版本号")
}

fn installed_server_version() -> Result<Version> {
    let output = std::process::Command::new(SERVER_INSTALL_PATH)
        .arg("--version")
        .output()
        .context("无法读取更新后的服务端版本")?;
    if !output.status.success() {
        bail!("更新后的服务端无法输出版本号。");
    }
    let mut version_output = output.stdout;
    version_output.extend_from_slice(&output.stderr);
    parse_server_version_output(&version_output)
}

fn write_update_installer(bytes: &[u8]) -> Result<PathBuf> {
    if !bytes.starts_with(b"#!/usr/bin/env bash") {
        bail!("下载的更新安装脚本格式不正确。");
    }
    for _ in 0..8 {
        let path = env::temp_dir().join(format!("orange-frp-update-{}.sh", random_token(24)));
        let mut file = match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("无法创建服务端更新临时文件"),
        };
        let result = (|| -> Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&path);
            return Err(error).context("写入服务端更新安装脚本失败");
        }
        return Ok(path);
    }
    bail!("无法分配服务端更新临时文件。");
}

fn run_server_update_installer(bytes: &[u8]) -> Result<()> {
    let installer = write_update_installer(bytes)?;
    let result = std::process::Command::new("bash")
        .arg(&installer)
        .status()
        .context("无法执行服务端更新安装脚本");
    let _ = fs::remove_file(&installer);
    let status = result?;
    if !status.success() {
        bail!("服务端更新安装失败，退出状态：{status}");
    }
    Ok(())
}

fn command_check_update(yes: bool) -> Result<bool> {
    let current = Version::parse(SERVER_VERSION).context("当前服务端版本号格式不正确")?;
    println!("当前服务端版本: v{current}");
    println!("正在检查服务端更新...");
    let client = update_http_client()?;
    let manifest_bytes = fetch_update_bytes(
        &client,
        SERVER_UPDATE_MANIFEST_URL,
        UPDATE_MANIFEST_MAX_BYTES,
        "服务端更新清单",
    )?;
    let (latest, expected_installer_sha256) = parse_server_update_manifest(&manifest_bytes)?;
    println!("更新通道版本: v{latest}");
    if latest == current {
        println!("{}", color("当前已是最新版本。", "32;1"));
        return Ok(false);
    }
    if latest < current {
        println!("{}", color("当前版本高于公开更新通道，无需更新。", "36;1"));
        return Ok(false);
    }
    println!(
        "{}",
        color(format!("发现服务端新版本：v{current} -> v{latest}"), "33;1")
    );
    if !yes && prompt_non_empty("是否立即更新？输入 YES 确认: ")? != "YES" {
        println!("已取消服务端更新。");
        return Ok(false);
    }
    require_root("更新服务端")?;
    println!("正在下载安装脚本...");
    let installer_bytes = fetch_update_bytes(
        &client,
        SERVER_UPDATE_INSTALLER_URL,
        UPDATE_INSTALLER_MAX_BYTES,
        "服务端更新安装脚本",
    )?;
    let installer_sha256 = sha256_hex(&installer_bytes);
    if !installer_sha256.eq_ignore_ascii_case(&expected_installer_sha256) {
        bail!("服务端更新安装脚本 SHA-256 校验失败，已拒绝执行。");
    }
    run_server_update_installer(&installer_bytes)?;
    let installed = installed_server_version()?;
    if installed != latest {
        bail!("更新安装完成，但实际服务端版本为 v{installed}，预期为 v{latest}。");
    }
    println!(
        "{}",
        color(
            format!("服务端已更新到 v{latest}，请重新输入 orange 打开菜单栏。"),
            "32;1"
        )
    );
    Ok(true)
}

fn command_init(
    api_bind: String,
    api_port: u16,
    frps_port: u16,
    frps_binary: String,
) -> Result<()> {
    require_root("初始化服务端")?;
    let storage = storage();
    storage.initialize()?;
    if storage.is_initialized()? {
        println!("服务端已经初始化。");
        return command_show();
    }
    let mut config = new_config(api_bind, api_port, frps_port, frps_binary);
    storage.create(&mut config)?;
    write_frps_config(&config)?;
    println!("\n初始化完成。现在开始添加第一个用户。");
    command_add_user(None, None, None, None, None)
}

fn command_setup(
    api_bind: String,
    api_port: u16,
    frps_port: u16,
    mut frps_binary: String,
    skip_frps_install: bool,
    force_frps: bool,
) -> Result<()> {
    require_root("安装服务端")?;
    if !skip_frps_install {
        frps_binary = install_frps_binary(force_frps)?;
    } else if find_executable(&frps_binary).is_none() {
        bail!("已跳过自动安装 frps，但系统中未找到 frps。");
    }

    let storage = storage();
    storage.initialize()?;
    let config = if storage.is_initialized()? {
        let mut config = storage.read()?;
        config.api_bind = api_bind;
        config.api_port = api_port;
        config.frps_bind_port = frps_port;
        config.frps_binary = frps_binary;
        config.updated_at = now_unix();
        storage.save(&mut config)?;
        println!("服务端配置已更新。");
        config
    } else {
        let mut config = new_config(api_bind, api_port, frps_port, frps_binary);
        storage.create(&mut config)?;
        println!("服务端 SQLite 基础配置已创建。");
        config
    };
    write_frps_config(&config)?;
    command_install_service()?;
    println!("SQLite 数据库：{}", storage.path().display());
    println!("当前用户数量：{}", config.users.len());
    println!();
    println!(
        "{}",
        color("安装完成。以后输入 orange 即可唤出菜单栏。", "32;1")
    );
    Ok(())
}

fn command_show() -> Result<()> {
    let config = storage().read()?;
    println!("服务端版本: v{SERVER_VERSION}");
    println!("服务器公网IP: {}", detect_public_ip());
    println!("认证端口: {}", config.api_port);
    println!("FRP控制端口: {}", config.frps_bind_port);
    println!("FRPS插件端口: {}（仅本机）", config.plugin_port);
    println!("用户数量: {}", config.users.len());
    println!("数据存储: {}", database_file().display());
    Ok(())
}

fn service_is_active() -> bool {
    matches!(
        std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", SERVICE_NAME])
            .status(),
        Ok(status) if status.success()
    )
}

fn restart_service_if_running() -> Result<()> {
    if !systemd_unit().exists() || !service_is_active() {
        return Ok(());
    }
    run_systemctl(&["restart", SERVICE_NAME])?;
    println!("系统服务已重启：{SERVICE_NAME}");
    Ok(())
}

fn account_exists(config: &ServerConfig, account: &str) -> bool {
    config.users.iter().any(|user| user.account == account)
}

fn validate_account(account: &str) -> Result<()> {
    let length = account.chars().count();
    if !(1..=64).contains(&length) || account.chars().any(char::is_control) {
        bail!("账号必须为 1-64 个字符且不能包含控制字符。");
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<()> {
    let length = password.chars().count();
    if !(8..=128).contains(&length) || password.chars().any(char::is_control) {
        bail!("密码必须为 8-128 个字符且不能包含控制字符。");
    }
    Ok(())
}

fn validate_tunnel_limit(limit: u32) -> Result<()> {
    if limit > MAX_TUNNEL_LIMIT {
        bail!("隧道数量限制必须在 0-{MAX_TUNNEL_LIMIT} 之间。");
    }
    Ok(())
}

fn prompt_tunnel_limit(label: &str, default: u32) -> Result<u32> {
    loop {
        let limit = prompt_u32(label, default)?;
        if let Err(error) = validate_tunnel_limit(limit) {
            println!("{error}");
        } else {
            return Ok(limit);
        }
    }
}

fn print_user_details(config: &ServerConfig, user: &ServerUser) -> Result<()> {
    println!();
    println!("{}", color("用户连接信息", "36;1"));
    println!("服务器公网IP: {}", detect_public_ip());
    println!("认证端口: {}", config.api_port);
    println!("FRP控制端口: {}", config.frps_bind_port);
    println!("账号: {}", user.account);
    match decrypt_user_password(&config.api_salt, &user.secret, &user.password_encrypted)? {
        Some(password) => println!("密码: {password}"),
        None => println!("密码: 旧数据库未保存可回显密码，请先修改该用户密码"),
    }
    println!("36位混合密钥: {}", user.secret);
    let tunnel_count = user.tunnels.len();
    let tunnel_limit = user.tunnel_limit as usize;
    println!("隧道数量: {tunnel_count} / {tunnel_limit}");
    println!("还可创建: {} 条", tunnel_limit.saturating_sub(tunnel_count));
    println!(
        "流量限制: {}",
        if user.traffic_limit_bytes == 0 {
            "不限流量".to_string()
        } else {
            format_bytes(user.traffic_limit_bytes)
        }
    );
    println!(
        "速度限制: {}",
        if user.speed_limit_mbps == 0 {
            "不限速".to_string()
        } else {
            format!("{} Mbps", user.speed_limit_mbps)
        }
    );
    Ok(())
}

fn select_user_index(config: &ServerConfig, label: &str) -> Result<Option<usize>> {
    if config.users.is_empty() {
        println!("当前没有用户。");
        return Ok(None);
    }
    println!();
    for (index, user) in config.users.iter().enumerate() {
        println!("{}. {}", index + 1, user.account);
    }
    let choice = prompt_non_empty(label)?;
    if let Some(index) = config.users.iter().position(|user| user.account == choice) {
        return Ok(Some(index));
    }
    if let Ok(index) = choice.parse::<usize>() {
        if (1..=config.users.len()).contains(&index) {
            return Ok(Some(index - 1));
        }
    }
    println!("未找到用户：{choice}");
    Ok(None)
}

fn resolve_user_index(
    config: &ServerConfig,
    account: Option<&str>,
    label: &str,
) -> Result<Option<usize>> {
    if let Some(account) = account {
        let found = config.users.iter().position(|user| user.account == account);
        if found.is_none() {
            println!("未找到用户：{account}");
        }
        Ok(found)
    } else {
        select_user_index(config, label)
    }
}

fn command_add_user(
    account: Option<String>,
    password: Option<String>,
    traffic_limit_gb: Option<f64>,
    speed_limit_mbps: Option<u32>,
    tunnel_limit: Option<u32>,
) -> Result<()> {
    require_root("添加用户")?;
    let storage = storage();
    let mut config = storage.read()?;
    let account = if let Some(account) = account {
        let account = account.trim().to_string();
        validate_account(&account)?;
        if account_exists(&config, &account) {
            bail!("账号已存在：{account}");
        }
        account
    } else {
        loop {
            let value = prompt_non_empty("请输入账号: ")?;
            if let Err(error) = validate_account(&value) {
                println!("{error}");
            } else if account_exists(&config, &value) {
                println!("账号已存在，请换一个账号。");
            } else {
                break value;
            }
        }
    };
    let password = match password {
        Some(password) if !password.is_empty() => password,
        Some(_) => bail!("密码不能为空。"),
        None => prompt_password(true)?,
    };
    validate_password(&password)?;
    let traffic_limit_gb = match traffic_limit_gb {
        Some(value) => value,
        None => prompt_f64("请输入流量限制 GB（0 表示不限，默认 0）: ", 0.0)?,
    };
    let speed_limit_mbps = match speed_limit_mbps {
        Some(value) => value,
        None => prompt_u32("请输入速度限制 Mbps（0 表示不限，默认 0）: ", 0)?,
    };
    let tunnel_limit = match tunnel_limit {
        Some(value) => {
            validate_tunnel_limit(value)?;
            value
        }
        None => prompt_tunnel_limit(
            "请输入隧道数量限制（0 表示禁止创建，最大 256，默认 5）: ",
            DEFAULT_NEW_USER_TUNNEL_LIMIT,
        )?,
    };
    let now = now_unix();
    let secret = random_secret(36);
    let user = ServerUser {
        id: new_user_id(),
        account: account.clone(),
        password_hash: hash_password(&password)?,
        password_encrypted: encrypt_user_password(&config.api_salt, &secret, &password)?,
        secret,
        tunnels: Vec::new(),
        tunnel_limit,
        traffic_limit_bytes: gb_to_bytes(traffic_limit_gb)?,
        traffic_used_bytes: 0,
        speed_limit_mbps,
        traffic_by_proxy: HashMap::new(),
        created_at: now,
        updated_at: now,
    };
    config.users.push(user);
    config.updated_at = now;
    storage.save(&mut config)?;
    restart_service_if_running()?;
    let user = config
        .users
        .iter()
        .find(|user| user.account == account)
        .context("用户添加后未找到")?;
    println!(
        "{}",
        color("用户已添加。密码已加密保存，可在查看用户中回显。", "32;1")
    );
    print_user_details(&config, user)?;
    Ok(())
}

fn command_view_users() -> Result<()> {
    require_root("查看用户")?;
    let config = storage().read()?;
    let Some(index) = select_user_index(&config, "请输入要查看的账号或序号: ")? else {
        return Ok(());
    };
    print_user_details(&config, &config.users[index])?;
    Ok(())
}

fn traffic_summary(user: &ServerUser) -> TrafficSummary {
    let mut ports = user
        .traffic_by_proxy
        .iter()
        .map(|(proxy_name, record)| PortTrafficUsage {
            proxy_name: proxy_name.clone(),
            protocol: record.protocol.clone(),
            remote_port: record.remote_port,
            traffic_in_bytes: record.traffic_in_bytes,
            traffic_out_bytes: record.traffic_out_bytes,
        })
        .collect::<Vec<_>>();
    ports.sort_by(|left, right| {
        left.remote_port
            .cmp(&right.remote_port)
            .then_with(|| left.protocol.cmp(&right.protocol))
    });
    let remaining_bytes = if user.traffic_limit_bytes == 0 {
        0
    } else {
        user.traffic_limit_bytes
            .saturating_sub(user.traffic_used_bytes)
    };
    TrafficSummary {
        limit_bytes: user.traffic_limit_bytes,
        used_bytes: user.traffic_used_bytes,
        remaining_bytes,
        speed_limit_mbps: user.speed_limit_mbps,
        exhausted: user.traffic_limit_bytes > 0
            && user.traffic_used_bytes >= user.traffic_limit_bytes,
        ports,
    }
}

fn print_user_traffic(user: &ServerUser) {
    let summary = traffic_summary(user);
    println!();
    println!("{}", color(format!("用户流量：{}", user.account), "36;1"));
    println!("已用流量: {}", format_bytes(summary.used_bytes));
    if summary.limit_bytes == 0 {
        println!("流量上限: 不限流量");
        println!("剩余流量: 不限流量");
    } else {
        println!("流量上限: {}", format_bytes(summary.limit_bytes));
        println!("剩余流量: {}", format_bytes(summary.remaining_bytes));
    }
    println!(
        "速度限制: {}",
        if summary.speed_limit_mbps == 0 {
            "不限速".to_string()
        } else {
            format!("{} Mbps", summary.speed_limit_mbps)
        }
    );
    println!(
        "配额状态: {}",
        if summary.exhausted {
            "已耗尽"
        } else {
            "可用"
        }
    );
    println!("端口流量:");
    if summary.ports.is_empty() {
        println!("  暂无端口流量记录");
    } else {
        for port in summary.ports {
            let total = port.traffic_in_bytes.saturating_add(port.traffic_out_bytes);
            println!(
                "  {} {} | 上行 {} | 下行 {} | 合计 {}",
                port.protocol,
                port.remote_port,
                format_bytes(port.traffic_in_bytes),
                format_bytes(port.traffic_out_bytes),
                format_bytes(total)
            );
        }
    }
}

fn command_view_traffic(account: Option<String>) -> Result<()> {
    let config = storage().read()?;
    let Some(index) = resolve_user_index(
        &config,
        account.as_deref(),
        "请输入要查看流量的账号或序号: ",
    )?
    else {
        return Ok(());
    };
    print_user_traffic(&config.users[index]);
    Ok(())
}

fn command_set_traffic_limit(account: Option<String>, gb: Option<f64>) -> Result<()> {
    require_root("修改用户流量限制")?;
    let storage = storage();
    let mut config = storage.read()?;
    let Some(index) = resolve_user_index(
        &config,
        account.as_deref(),
        "请输入要修改流量限制的账号或序号: ",
    )?
    else {
        return Ok(());
    };
    let gb = match gb {
        Some(value) => value,
        None => prompt_f64("请输入新的流量限制 GB（0 表示不限）: ", 0.0)?,
    };
    config.users[index].traffic_limit_bytes = gb_to_bytes(gb)?;
    config.users[index].updated_at = now_unix();
    config.updated_at = now_unix();
    storage.save(&mut config)?;
    restart_service_if_running()?;
    println!("用户流量限制已修改并应用。");
    print_user_traffic(&config.users[index]);
    Ok(())
}

fn command_set_traffic_used(account: Option<String>, gb: Option<f64>) -> Result<()> {
    require_root("修改用户已用流量")?;
    let storage = storage();
    let mut config = storage.read()?;
    let Some(index) = resolve_user_index(
        &config,
        account.as_deref(),
        "请输入要修改已用流量的账号或序号: ",
    )?
    else {
        return Ok(());
    };
    let gb = match gb {
        Some(value) => value,
        None => prompt_f64("请输入新的已用流量 GB: ", 0.0)?,
    };
    config.users[index].traffic_used_bytes = gb_to_bytes(gb)?;
    config.users[index].updated_at = now_unix();
    config.updated_at = now_unix();
    storage.save(&mut config)?;
    restart_service_if_running()?;
    println!("用户已用流量已修改并应用。");
    print_user_traffic(&config.users[index]);
    Ok(())
}

fn command_set_speed_limit(account: Option<String>, mbps: Option<u32>) -> Result<()> {
    require_root("修改用户速度限制")?;
    let storage = storage();
    let mut config = storage.read()?;
    let Some(index) = resolve_user_index(
        &config,
        account.as_deref(),
        "请输入要修改速度限制的账号或序号: ",
    )?
    else {
        return Ok(());
    };
    let mbps = match mbps {
        Some(value) => value,
        None => prompt_u32("请输入新的速度限制 Mbps（0 表示不限）: ", 0)?,
    };
    config.users[index].speed_limit_mbps = mbps;
    config.users[index].updated_at = now_unix();
    config.updated_at = now_unix();
    storage.save(&mut config)?;
    restart_service_if_running()?;
    println!("用户速度限制已修改并应用。");
    print_user_traffic(&config.users[index]);
    Ok(())
}

fn command_set_tunnel_limit(account: Option<String>, limit: Option<u32>) -> Result<()> {
    require_root("修改用户隧道数量限制")?;
    let storage = storage();
    let mut config = storage.read()?;
    let Some(index) = resolve_user_index(
        &config,
        account.as_deref(),
        "请输入要修改隧道数量限制的账号或序号: ",
    )?
    else {
        return Ok(());
    };
    let limit = match limit {
        Some(value) => {
            validate_tunnel_limit(value)?;
            value
        }
        None => prompt_tunnel_limit(
            "请输入新的隧道数量限制（0 表示禁止创建，最大 256）: ",
            config.users[index].tunnel_limit,
        )?,
    };
    config.users[index].tunnel_limit = limit;
    config.users[index].updated_at = now_unix();
    config.updated_at = now_unix();
    storage.save(&mut config)?;
    restart_service_if_running()?;
    println!("用户隧道数量限制已修改并应用。");
    print_user_details(&config, &config.users[index])?;
    Ok(())
}

fn command_delete_user() -> Result<()> {
    require_root("删除用户")?;
    let storage = storage();
    let mut config = storage.read()?;
    let Some(index) = select_user_index(&config, "请输入要删除的账号或序号: ")? else {
        return Ok(());
    };
    let account = config.users[index].account.clone();
    if prompt_non_empty(&format!("确认删除用户 {account}？输入 YES 确认: "))? != "YES" {
        println!("已取消删除。");
        return Ok(());
    }
    config.users.remove(index);
    config.updated_at = now_unix();
    storage.save(&mut config)?;
    restart_service_if_running()?;
    println!("用户已删除：{account}");
    Ok(())
}

fn command_change_account() -> Result<()> {
    require_root("修改账号")?;
    let storage = storage();
    let mut config = storage.read()?;
    let Some(index) = select_user_index(&config, "请输入要修改的账号或序号: ")? else {
        return Ok(());
    };
    let account = loop {
        let value = prompt_non_empty("请输入新账号: ")?;
        if let Err(error) = validate_account(&value) {
            println!("{error}");
        } else if config
            .users
            .iter()
            .enumerate()
            .any(|(item_index, user)| item_index != index && user.account == value)
        {
            println!("账号已存在，请换一个账号。");
        } else {
            break value;
        }
    };
    config.users[index].account = account;
    config.users[index].updated_at = now_unix();
    config.updated_at = now_unix();
    storage.save(&mut config)?;
    restart_service_if_running()?;
    println!("账号已修改并应用。");
    Ok(())
}

fn command_change_password() -> Result<()> {
    require_root("修改密码")?;
    let storage = storage();
    let mut config = storage.read()?;
    let Some(index) = select_user_index(&config, "请输入要修改密码的账号或序号: ")?
    else {
        return Ok(());
    };
    let password = prompt_password(true)?;
    validate_password(&password)?;
    config.users[index].password_encrypted =
        encrypt_user_password(&config.api_salt, &config.users[index].secret, &password)?;
    config.users[index].password_hash = hash_password(&password)?;
    config.users[index].updated_at = now_unix();
    config.updated_at = now_unix();
    storage.save(&mut config)?;
    restart_service_if_running()?;
    println!("密码已修改并加密保存，可在查看用户中回显。");
    Ok(())
}

fn command_rotate_key(yes: bool) -> Result<()> {
    require_root("重置密钥")?;
    if !yes && prompt_non_empty("重置密钥后旧客户端需要重新登录，输入 YES 确认: ")? != "YES"
    {
        println!("已取消重置密钥。");
        return Ok(());
    }
    let storage = storage();
    let mut config = storage.read()?;
    let Some(index) = select_user_index(&config, "请输入要重置密钥的账号或序号: ")?
    else {
        return Ok(());
    };
    let password = decrypt_user_password(
        &config.api_salt,
        &config.users[index].secret,
        &config.users[index].password_encrypted,
    )?;
    let new_secret = random_secret(36);
    config.users[index].password_encrypted = match password {
        Some(password) => encrypt_user_password(&config.api_salt, &new_secret, &password)?,
        None => String::new(),
    };
    config.users[index].secret = new_secret;
    config.users[index].updated_at = now_unix();
    config.updated_at = now_unix();
    storage.save(&mut config)?;
    restart_service_if_running()?;
    println!("密钥已重置。密钥仅在本次显示，请妥善保管。");
    println!("新密钥: {}", config.users[index].secret);
    Ok(())
}

fn pause() -> Result<()> {
    print!("{}", color("\n按 Enter 返回菜单...", "90"));
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(())
}

fn command_menu() -> Result<()> {
    require_root("打开菜单")?;
    loop {
        print!("\x1b[2J\x1b[H");
        print_title();
        println!();
        println!("1. 添加用户");
        println!("2. 查看用户");
        println!("3. 删除用户");
        println!("4. 查看用户流量");
        println!("5. 修改用户流量限制");
        println!("6. 修改用户已用流量");
        println!("7. 修改用户速度限制");
        println!("8. 修改用户隧道数量限制");
        println!("9. 检查服务端更新");
        println!("10. 卸载服务端");
        println!("0. 退出菜单");
        println!();
        let choice = prompt_non_empty("请选择操作: ")?;
        let result = match choice.as_str() {
            "1" => command_add_user(None, None, None, None, None),
            "2" => command_view_users(),
            "3" => command_delete_user(),
            "4" => command_view_traffic(None),
            "5" => command_set_traffic_limit(None, None),
            "6" => command_set_traffic_used(None, None),
            "7" => command_set_speed_limit(None, None),
            "8" => command_set_tunnel_limit(None, None),
            "9" => match command_check_update(false) {
                Ok(true) => return Ok(()),
                Ok(false) => Ok(()),
                Err(error) => Err(error),
            },
            "10" => {
                let confirm =
                    prompt_non_empty("将停止服务并完全卸载 Orange FRP 服务端，输入 YES 确认: ")?;
                if confirm == "YES" {
                    command_uninstall(true)?;
                    return Ok(());
                }
                println!("已取消卸载。");
                Ok(())
            }
            "0" | "q" | "Q" => return Ok(()),
            _ => {
                println!("无效选择，请重新输入。");
                Ok(())
            }
        };
        if let Err(error) = result {
            eprintln!("{}", color(format!("操作失败：{error}"), "31;1"));
        }
        pause()?;
    }
}

fn find_executable(candidate: &str) -> Option<PathBuf> {
    let path = PathBuf::from(candidate);
    if path.is_file() {
        return Some(path);
    }
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|directory| directory.join(candidate))
            .find(|path| path.is_file())
    })
}

fn find_frps_binary(config: &ServerConfig) -> Result<PathBuf> {
    for candidate in [
        config.frps_binary.as_str(),
        "frps",
        FRPS_INSTALL_PATH,
        "/usr/bin/frps",
    ] {
        if let Some(path) = find_executable(candidate) {
            return Ok(path);
        }
    }
    bail!("未找到 frps，请重新运行安装脚本。")
}

async fn detect_frps_version(config: &ServerConfig) -> String {
    let Ok(binary) = find_frps_binary(config) else {
        return String::new();
    };
    let Ok(output) = Command::new(binary)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
    else {
        return String::new();
    };
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_frp_version_text(&text).unwrap_or_default()
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

fn write_frps_config(config: &ServerConfig) -> Result<()> {
    fs::create_dir_all(config_dir())?;
    fs::create_dir_all(LOG_DIR)?;
    let content = [
        "bindAddr = \"0.0.0.0\"".to_string(),
        format!("bindPort = {}", config.frps_bind_port),
        "proxyBindAddr = \"127.0.0.1\"".to_string(),
        String::new(),
        "[auth]".to_string(),
        "method = \"token\"".to_string(),
        format!("token = {}", toml_string(&config.frps_token)),
        String::new(),
        "[[httpPlugins]]".to_string(),
        "name = \"orange-control\"".to_string(),
        format!("addr = \"127.0.0.1:{}\"", config.plugin_port),
        "path = \"/handler\"".to_string(),
        "ops = [\"Login\", \"NewProxy\", \"CloseProxy\"]".to_string(),
        String::new(),
        "[log]".to_string(),
        format!(
            "to = {}",
            toml_string(&Path::new(LOG_DIR).join("frps.log").display().to_string())
        ),
        "level = \"info\"".to_string(),
        "maxDays = 7".to_string(),
        String::new(),
    ]
    .join("\n");
    let path = frps_config_file();
    atomic_write_file(&path, content.as_bytes(), 0o600)?;
    Ok(())
}

fn normalize_user_tunnels(
    config: &ServerConfig,
    user_index: usize,
    tunnels: &[Tunnel],
) -> Result<Vec<Tunnel>> {
    let tunnel_limit = config.users[user_index].tunnel_limit as usize;
    let current_tunnel_count = config.users[user_index].tunnels.len();
    if tunnels.len() > tunnel_limit && tunnels.len() > current_tunnel_count {
        bail!("超出隧道数量限制：最多可创建 {tunnel_limit} 条隧道。");
    }
    if tunnels.len() > MAX_TUNNELS_PER_USER {
        bail!("隧道数量超过系统最大值 {MAX_TUNNELS_PER_USER}。");
    }
    let mut normalized = normalize_tunnels(tunnels)?;
    let current = &config.users[user_index];
    let existing_backends = current
        .tunnels
        .iter()
        .map(|tunnel| (tunnel.id.clone(), tunnel.backend_port))
        .collect::<HashMap<_, _>>();
    let backend_ports = config
        .users
        .iter()
        .flat_map(|user| user.tunnels.iter().map(|tunnel| tunnel.backend_port))
        .collect::<HashSet<_>>();
    let mut used_ports = [config.api_port, config.frps_bind_port, config.plugin_port]
        .into_iter()
        .collect::<HashSet<_>>();
    for user in &config.users {
        for tunnel in &user.tunnels {
            used_ports.insert(tunnel.backend_port);
            if user.id != current.id {
                used_ports.insert(tunnel.remote_port);
            }
        }
    }
    for tunnel in &normalized {
        used_ports.insert(tunnel.remote_port);
    }

    let mut tunnel_ids = HashSet::new();
    let mut proxy_names = HashSet::new();
    for tunnel in &mut normalized {
        if tunnel.id.len() > 64
            || !tunnel.id.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '-' || character == '_'
            })
        {
            bail!("隧道 ID 格式不正确。");
        }
        tunnel.proxy_name = proxy_name_for(&tunnel.id);
        if !tunnel_ids.insert(tunnel.id.clone()) || !proxy_names.insert(tunnel.proxy_name.clone()) {
            bail!("隧道 ID 重复：{}", tunnel.id);
        }
        if [config.api_port, config.frps_bind_port, config.plugin_port]
            .contains(&tunnel.remote_port)
        {
            bail!("远程端口 {} 是服务端保留端口。", tunnel.remote_port);
        }
        if backend_ports.contains(&tunnel.remote_port) {
            bail!("远程端口 {} 与 FRPS 本机后端端口冲突。", tunnel.remote_port);
        }
        for (index, user) in config.users.iter().enumerate() {
            if index == user_index {
                continue;
            }
            for other in &user.tunnels {
                if other.protocol == tunnel.protocol && other.remote_port == tunnel.remote_port {
                    bail!(
                        "{} 远程端口 {} 已被用户 {} 的隧道 {} 占用。",
                        tunnel.protocol,
                        tunnel.remote_port,
                        user.account,
                        other.name
                    );
                }
                if other.proxy_name == tunnel.proxy_name {
                    bail!("隧道标识冲突：{}", tunnel.proxy_name);
                }
            }
        }
        tunnel.backend_port = if let Some(port) = existing_backends.get(&tunnel.id) {
            *port
        } else {
            allocate_backend_port(&mut used_ports)?
        };
    }
    Ok(normalized)
}

fn api_error(status: StatusCode, message: &str) -> axum::response::Response {
    (status, Json(json!({"ok": false, "message": message}))).into_response()
}

fn encrypted_response(
    api_salt: &str,
    user: &ServerUser,
    status: StatusCode,
    body: Value,
) -> axum::response::Response {
    match encrypt_payload(&user.secret, api_salt, body) {
        Ok(envelope) => (status, Json(envelope)).into_response(),
        Err(error) => {
            eprintln!("加密 API 响应失败：{error}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "服务器内部错误")
        }
    }
}

fn secure_equal(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn decrypt_and_auth(
    config: &ServerConfig,
    envelope: &Envelope,
    expected_operation: &str,
) -> Result<AuthContext> {
    for (index, user) in config.users.iter().enumerate() {
        let Ok(payload) = decrypt_payload(&user.secret, &config.api_salt, envelope) else {
            continue;
        };
        let operation_ok = payload.get("op").and_then(Value::as_str) == Some(expected_operation);
        let account_ok =
            payload.get("account").and_then(Value::as_str) == Some(user.account.as_str());
        let key_ok = payload
            .get("key")
            .and_then(Value::as_str)
            .map(|key| secure_equal(key, &user.secret))
            .unwrap_or(false);
        let password_ok = payload
            .get("password")
            .and_then(Value::as_str)
            .map(|password| verify_password(&user.password_hash, password))
            .unwrap_or(false);
        if operation_ok && account_ok && key_ok && password_ok {
            return Ok(AuthContext {
                user_index: index,
                payload,
            });
        }
    }
    bail!("认证失败")
}

async fn check_rate(state: &ApiState, ip: IpAddr, cost: f64) -> bool {
    state.rate_limit.lock().await.allow(ip, cost)
}

async fn frps_accepting_connections(port: u16) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_millis(750),
            tokio::net::TcpStream::connect(("127.0.0.1", port)),
        )
        .await,
        Ok(Ok(_))
    )
}

async fn accept_replay(
    state: &ApiState,
    user: &ServerUser,
    operation: &str,
    envelope: &Envelope,
) -> bool {
    state
        .replay
        .lock()
        .await
        .accept(&user.id, operation, &envelope.nonce)
}

async fn hello(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> axum::response::Response {
    if !check_rate(&state, peer.ip(), 1.0).await {
        return api_error(StatusCode::TOO_MANY_REQUESTS, "请求过于频繁");
    }
    let (api_salt, api_port, frps_bind_port) = {
        let config = state.config.read().await;
        (
            config.api_salt.clone(),
            config.api_port,
            config.frps_bind_port,
        )
    };
    let frps_online = state.frps_online.load(Ordering::Relaxed)
        && frps_accepting_connections(frps_bind_port).await;
    Json(json!({
        "ok": true,
        "version": 1,
        "server_version": SERVER_VERSION,
        "salt": api_salt,
        "api_port": api_port,
        "frps_port": frps_bind_port,
        "frps_version": state.frps_version,
        "frps_online": frps_online,
        "server_time": now_unix(),
    }))
    .into_response()
}

async fn login(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(envelope): Json<Envelope>,
) -> axum::response::Response {
    if !check_rate(&state, peer.ip(), 8.0).await {
        return api_error(StatusCode::TOO_MANY_REQUESTS, "登录请求过于频繁");
    }
    let (api_salt, frps_bind_port, configured_frps_token, user) = {
        let config = state.config.read().await;
        let auth = match decrypt_and_auth(&config, &envelope, "login") {
            Ok(auth) => auth,
            Err(_) => return api_error(StatusCode::UNAUTHORIZED, "认证失败"),
        };
        (
            config.api_salt.clone(),
            config.frps_bind_port,
            config.frps_token.clone(),
            config.users[auth.user_index].clone(),
        )
    };
    if !accept_replay(&state, &user, "login", &envelope).await {
        return api_error(StatusCode::CONFLICT, "请求已被处理，请重新发起登录");
    }
    let traffic = traffic_summary(&user);
    let frps_online = state.frps_online.load(Ordering::Relaxed)
        && frps_accepting_connections(frps_bind_port).await;
    let frps_token = if traffic.exhausted || !frps_online {
        String::new()
    } else {
        configured_frps_token
    };
    encrypted_response(
        &api_salt,
        &user,
        StatusCode::OK,
        json!({
            "ok": true,
            "frps_port": frps_bind_port,
            "frps_token": frps_token,
            "tunnels": user.tunnels,
            "tunnel_limit": user.tunnel_limit,
            "frps_version": state.frps_version,
            "traffic": traffic,
            "server_time": now_unix(),
        }),
    )
}

async fn tunnels(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(envelope): Json<Envelope>,
) -> axum::response::Response {
    if !check_rate(&state, peer.ip(), 3.0).await {
        return api_error(StatusCode::TOO_MANY_REQUESTS, "请求过于频繁");
    }
    let mut config = state.config.write().await;
    let auth = match decrypt_and_auth(&config, &envelope, "tunnels") {
        Ok(auth) => auth,
        Err(_) => return api_error(StatusCode::UNAUTHORIZED, "认证失败"),
    };
    let user_for_replay = config.users[auth.user_index].clone();
    if !accept_replay(&state, &user_for_replay, "tunnels", &envelope).await {
        return encrypted_response(
            &config.api_salt,
            &user_for_replay,
            StatusCode::CONFLICT,
            json!({"ok": false, "message": "重复请求已被拒绝"}),
        );
    }
    match auth.payload.get("action").and_then(Value::as_str) {
        Some("list") => {
            let user = &config.users[auth.user_index];
            encrypted_response(
                &config.api_salt,
                user,
                StatusCode::OK,
                json!({
                    "ok": true,
                    "tunnels": user.tunnels,
                    "tunnel_limit": user.tunnel_limit,
                    "traffic": traffic_summary(user)
                }),
            )
        }
        Some("save") => {
            if traffic_summary(&config.users[auth.user_index]).exhausted {
                return encrypted_response(
                    &config.api_salt,
                    &config.users[auth.user_index],
                    StatusCode::FORBIDDEN,
                    json!({"ok": false, "message": "流量配额已用尽，无法修改或启动隧道。"}),
                );
            }
            let tunnels: Vec<Tunnel> = match serde_json::from_value(
                auth.payload.get("tunnels").cloned().unwrap_or(Value::Null),
            ) {
                Ok(tunnels) => tunnels,
                Err(_) => {
                    return encrypted_response(
                        &config.api_salt,
                        &config.users[auth.user_index],
                        StatusCode::BAD_REQUEST,
                        json!({"ok": false, "message": "隧道列表格式不正确"}),
                    )
                }
            };
            let normalized = match normalize_user_tunnels(&config, auth.user_index, &tunnels) {
                Ok(tunnels) => tunnels,
                Err(error) => {
                    return encrypted_response(
                        &config.api_salt,
                        &config.users[auth.user_index],
                        StatusCode::BAD_REQUEST,
                        json!({"ok": false, "message": error.to_string()}),
                    )
                }
            };
            let original = config.clone();
            let mut candidate = config.clone();
            let user = &mut candidate.users[auth.user_index];
            for record in user.traffic_by_proxy.values_mut() {
                record.active = false;
            }
            for tunnel in &normalized {
                user.traffic_by_proxy
                    .entry(tunnel.proxy_name.clone())
                    .or_insert_with(|| ProxyTrafficRecord {
                        protocol: tunnel.protocol.clone(),
                        remote_port: tunnel.remote_port,
                        active: true,
                        ..ProxyTrafficRecord::default()
                    })
                    .active = true;
            }
            user.tunnels = normalized;
            user.updated_at = now_unix();
            candidate.updated_at = now_unix();
            if let Err(error) = state.storage.save(&mut candidate) {
                eprintln!("保存隧道配置失败：{error}");
                return encrypted_response(
                    &config.api_salt,
                    &config.users[auth.user_index],
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"ok": false, "message": "服务器内部错误"}),
                );
            }
            if let Some(controller) = &state.controller {
                if let Err(error) = controller.reconcile(&candidate).await {
                    let mut rollback = original;
                    rollback.revision = candidate.revision;
                    let rollback_result = state.storage.save(&mut rollback);
                    if rollback_result.is_ok() {
                        let _ = controller.reconcile(&rollback).await;
                        *config = rollback;
                    }
                    return encrypted_response(
                        &config.api_salt,
                        &config.users[auth.user_index],
                        StatusCode::CONFLICT,
                        json!({"ok": false, "message": format!("公网端口监听失败：{error}")}),
                    );
                }
            }
            *config = candidate;
            let user = &config.users[auth.user_index];
            encrypted_response(
                &config.api_salt,
                user,
                StatusCode::OK,
                json!({
                    "ok": true,
                    "tunnels": user.tunnels,
                    "tunnel_limit": user.tunnel_limit,
                    "traffic": traffic_summary(user)
                }),
            )
        }
        _ => encrypted_response(
            &config.api_salt,
            &config.users[auth.user_index],
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "message": "未知隧道操作"}),
        ),
    }
}

async fn usage(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(envelope): Json<Envelope>,
) -> axum::response::Response {
    if !check_rate(&state, peer.ip(), 2.0).await {
        return api_error(StatusCode::TOO_MANY_REQUESTS, "请求过于频繁");
    }
    let config = state.config.read().await;
    let auth = match decrypt_and_auth(&config, &envelope, "usage") {
        Ok(auth) => auth,
        Err(_) => return api_error(StatusCode::UNAUTHORIZED, "认证失败"),
    };
    let user = &config.users[auth.user_index];
    if !accept_replay(&state, user, "usage", &envelope).await {
        return encrypted_response(
            &config.api_salt,
            user,
            StatusCode::CONFLICT,
            json!({"ok": false, "message": "重复请求已被拒绝"}),
        );
    }
    encrypted_response(
        &config.api_salt,
        user,
        StatusCode::OK,
        json!({
            "ok": true,
            "tunnel_limit": user.tunnel_limit,
            "traffic": traffic_summary(user)
        }),
    )
}

async fn frps_plugin(
    State(state): State<ApiState>,
    Query(query): Query<HashMap<String, String>>,
    Json(request): Json<Value>,
) -> axum::response::Response {
    let operation = query.get("op").map(String::as_str).unwrap_or_default();
    let content = request.get("content").cloned().unwrap_or(Value::Null);
    let config = state.config.read().await;
    match operation {
        "Login" => {
            let account = content
                .get("user")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let secret = content
                .get("metas")
                .and_then(|metas| metas.get("orange_secret"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            plugin_login_response(&config, account, secret)
        }
        "NewProxy" => {
            let account = content
                .get("user")
                .and_then(|user| user.get("user"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let secret = content
                .get("user")
                .and_then(|user| user.get("metas"))
                .and_then(|metas| metas.get("orange_secret"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let proxy_name = content
                .get("proxy_name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let proxy_type = content
                .get("proxy_type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let remote_port = content
                .get("remote_port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .unwrap_or_default();
            plugin_proxy_response(
                &config,
                account,
                secret,
                proxy_name,
                proxy_type,
                remote_port,
            )
        }
        "CloseProxy" => Json(json!({"reject": false, "unchange": true})).into_response(),
        _ => Json(json!({
            "reject": true,
            "reject_reason": "unsupported operation"
        }))
        .into_response(),
    }
}

fn plugin_login_response(
    config: &ServerConfig,
    account: &str,
    secret: &str,
) -> axum::response::Response {
    let Some(user) = config.users.iter().find(|user| user.account == account) else {
        return Json(json!({"reject": true, "reject_reason": "invalid user"})).into_response();
    };
    if !secure_equal(secret, &user.secret) {
        return Json(json!({"reject": true, "reject_reason": "invalid user secret"}))
            .into_response();
    }
    if traffic_summary(user).exhausted {
        return Json(json!({"reject": true, "reject_reason": "traffic quota exhausted"}))
            .into_response();
    }
    Json(json!({"reject": false, "unchange": true})).into_response()
}

fn plugin_proxy_response(
    config: &ServerConfig,
    account: &str,
    secret: &str,
    proxy_name: &str,
    proxy_type: &str,
    remote_port: u16,
) -> axum::response::Response {
    let Some(user) = config.users.iter().find(|user| user.account == account) else {
        return Json(json!({"reject": true, "reject_reason": "invalid user"})).into_response();
    };
    if !secure_equal(secret, &user.secret) || traffic_summary(user).exhausted {
        return Json(json!({"reject": true, "reject_reason": "user is not authorized"}))
            .into_response();
    }
    let allowed = user.tunnels.iter().any(|tunnel| {
        let frps_proxy_name = format!("{account}.{}", tunnel.proxy_name);
        (tunnel.proxy_name == proxy_name || frps_proxy_name == proxy_name)
            && tunnel.protocol.eq_ignore_ascii_case(proxy_type)
            && tunnel.backend_port == remote_port
    });
    if !allowed {
        return Json(json!({
            "reject": true,
            "reject_reason": "proxy is not registered in Orange FRP"
        }))
        .into_response();
    }
    Json(json!({"reject": false, "unchange": true})).into_response()
}

async fn start_frps(config: &ServerConfig) -> Result<Child> {
    write_frps_config(config)?;
    let binary = find_frps_binary(config)?;
    println!(
        "启动 frps: {} -c {}",
        binary.display(),
        frps_config_file().display()
    );
    Command::new(binary)
        .arg("-c")
        .arg(frps_config_file())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("启动 frps 失败")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            }
            Err(error) => {
                eprintln!("注册 SIGTERM 处理器失败：{error}");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn command_serve(api_only: bool) -> Result<()> {
    let storage = storage();
    let config = storage.read()?;
    write_frps_config(&config)?;
    let frps_version = detect_frps_version(&config).await;
    let shared_config = Arc::new(RwLock::new(config.clone()));
    let frps_online = Arc::new(AtomicBool::new(false));
    let cancel = CancellationToken::new();

    let (traffic_controller, accounting_receiver) = TrafficController::new(&config);
    let (controller, accounting_task) = if api_only {
        drop(accounting_receiver);
        (None, None)
    } else {
        traffic_controller.reconcile(&config).await?;
        let task = spawn_accounting_task(
            storage.clone(),
            shared_config.clone(),
            accounting_receiver,
            cancel.child_token(),
        );
        (Some(traffic_controller), Some(task))
    };

    let state = ApiState {
        config: shared_config.clone(),
        storage: storage.clone(),
        controller: controller.clone(),
        frps_version,
        frps_online: frps_online.clone(),
        replay: Arc::new(Mutex::new(ReplayGuard::default())),
        rate_limit: Arc::new(Mutex::new(ApiRateLimiter::default())),
    };
    let api_address: SocketAddr = format!("{}:{}", config.api_bind, config.api_port)
        .parse()
        .context("认证 API 监听地址无效")?;
    let plugin_address: SocketAddr = format!("127.0.0.1:{}", config.plugin_port)
        .parse()
        .context("FRPS 插件监听地址无效")?;
    let api_listener = tokio::net::TcpListener::bind(api_address).await?;
    let plugin_listener = tokio::net::TcpListener::bind(plugin_address).await?;
    let api_app = Router::new()
        .route("/api/hello", get(hello))
        .route("/api/login", post(login))
        .route("/api/tunnels", post(tunnels))
        .route("/api/usage", post(usage))
        .layer(DefaultBodyLimit::max(API_BODY_LIMIT_BYTES))
        .with_state(state.clone());
    let plugin_app = Router::new()
        .route("/handler", post(frps_plugin))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);
    println!("认证 API 已启动: http://{}", api_listener.local_addr()?);
    println!(
        "FRPS 鉴权插件已启动: http://{}",
        plugin_listener.local_addr()?
    );

    let mut api_task = tokio::spawn(async move {
        axum::serve(
            api_listener,
            api_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });
    let mut plugin_task =
        tokio::spawn(async move { axum::serve(plugin_listener, plugin_app).await });
    let mut frps = if api_only {
        None
    } else {
        let child = start_frps(&config).await?;
        frps_online.store(true, Ordering::Relaxed);
        Some(child)
    };

    let outcome = if let Some(child) = frps.as_mut() {
        tokio::select! {
            _ = shutdown_signal() => Ok(()),
            result = &mut api_task => match result {
                Ok(Ok(())) => Err(anyhow::anyhow!("认证 API 意外退出")),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
            result = &mut plugin_task => match result {
                Ok(Ok(())) => Err(anyhow::anyhow!("FRPS 插件服务意外退出")),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
            status = child.wait() => {
                frps_online.store(false, Ordering::Relaxed);
                Err(anyhow::anyhow!(
                    "frps 意外退出：{:?}",
                    status.ok().and_then(|status| status.code())
                ))
            }
        }
    } else {
        tokio::select! {
            _ = shutdown_signal() => Ok(()),
            result = &mut api_task => match result {
                Ok(Ok(())) => Err(anyhow::anyhow!("认证 API 意外退出")),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
            result = &mut plugin_task => match result {
                Ok(Ok(())) => Err(anyhow::anyhow!("FRPS 插件服务意外退出")),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
        }
    };

    cancel.cancel();
    if let Some(controller) = &controller {
        controller.shutdown().await;
    }
    if let Some(task) = accounting_task {
        let _ = task.await;
    }
    if let Some(child) = frps.as_mut() {
        if child.id().is_some() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }
    api_task.abort();
    plugin_task.abort();
    let _ = api_task.await;
    let _ = plugin_task.await;
    frps_online.store(false, Ordering::Relaxed);
    outcome
}

fn command_install_service() -> Result<()> {
    require_root("安装系统服务")?;
    let config = storage().read()?;
    write_frps_config(&config)?;
    let executable = if Path::new(SERVER_INSTALL_PATH).is_file() {
        PathBuf::from(SERVER_INSTALL_PATH)
    } else {
        env::current_exe().context("无法定位当前可执行文件")?
    };
    let unit = [
        "[Unit]".to_string(),
        "Description=Orange FRP Server".to_string(),
        "After=network-online.target".to_string(),
        "Wants=network-online.target".to_string(),
        String::new(),
        "[Service]".to_string(),
        "Type=simple".to_string(),
        format!("ExecStart={} serve", executable.display()),
        "Restart=always".to_string(),
        "RestartSec=3".to_string(),
        "KillSignal=SIGINT".to_string(),
        "KillMode=mixed".to_string(),
        "TimeoutStopSec=15".to_string(),
        "UMask=0077".to_string(),
        "LimitNOFILE=131072".to_string(),
        "NoNewPrivileges=true".to_string(),
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE".to_string(),
        "PrivateDevices=true".to_string(),
        "PrivateTmp=true".to_string(),
        "ProtectClock=true".to_string(),
        "ProtectControlGroups=true".to_string(),
        "ProtectHome=true".to_string(),
        "ProtectHostname=true".to_string(),
        "ProtectKernelLogs=true".to_string(),
        "ProtectKernelModules=true".to_string(),
        "ProtectKernelTunables=true".to_string(),
        "ProtectSystem=strict".to_string(),
        format!("ReadWritePaths={} {}", config_dir().display(), LOG_DIR),
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX".to_string(),
        "LockPersonality=true".to_string(),
        "RestrictNamespaces=true".to_string(),
        "RestrictRealtime=true".to_string(),
        "RestrictSUIDSGID=true".to_string(),
        "SystemCallArchitectures=native".to_string(),
        "Environment=RUST_BACKTRACE=1".to_string(),
        String::new(),
        "[Install]".to_string(),
        "WantedBy=multi-user.target".to_string(),
        String::new(),
    ]
    .join("\n");
    atomic_write_file(&systemd_unit(), unit.as_bytes(), 0o644)?;
    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&["enable", SERVICE_NAME])?;
    if service_is_active() {
        run_systemctl(&["restart", SERVICE_NAME])?;
    } else {
        run_systemctl(&["start", SERVICE_NAME])?;
    }
    println!("系统服务已安装并启动：{SERVICE_NAME}");
    println!("查看日志：journalctl -u {SERVICE_NAME} -f");
    Ok(())
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("systemctl {} 执行失败", args.join(" ")))?;
    if !status.success() {
        bail!("systemctl {} 执行失败", args.join(" "));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn install_frps_binary(force: bool) -> Result<String> {
    if !force {
        if let Some(existing) = find_executable("frps") {
            println!("已找到 frps：{}", existing.display());
            return Ok(existing.display().to_string());
        }
    }
    if env::consts::ARCH != "x86_64" {
        bail!(
            "Orange FRP 当前自动下载的 frps{} 仅适配 Linux x86_64，当前架构为 {}。",
            ORANGE_FRPS_VERSION,
            env::consts::ARCH
        );
    }
    let client = reqwest::blocking::Client::builder()
        .user_agent("orange-frp-installer")
        .timeout(Duration::from_secs(120))
        .build()?;
    println!("正在下载 Orange FRP：frps{}", ORANGE_FRPS_VERSION);
    let bytes = client
        .get(ORANGE_FRPS_DOWNLOAD_URL)
        .send()?
        .error_for_status()?
        .bytes()?;
    let digest = sha256_hex(&bytes);
    if digest != ORANGE_FRPS_SHA256 {
        bail!("frps 下载文件 SHA-256 校验失败，拒绝安装。");
    }
    let target = PathBuf::from(FRPS_INSTALL_PATH);
    let temporary = target.with_file_name(format!(".frps.orange-download-{}", std::process::id()));
    fs::write(&temporary, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))?;
    }
    let output = std::process::Command::new(&temporary)
        .arg("--version")
        .output()
        .context("无法执行下载后的 frps")?;
    let version_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let version = parse_frp_version_text(&version_text).unwrap_or_default();
    if !output.status.success() || version != ORANGE_FRPS_VERSION {
        let _ = fs::remove_file(&temporary);
        bail!("下载后的 frps 版本验证失败：{version}");
    }
    fs::rename(&temporary, &target)?;
    fs::create_dir_all(config_dir())?;
    atomic_write_file(
        &frps_owned_marker(),
        format!("{digest}  {FRPS_INSTALL_PATH}\n").as_bytes(),
        0o600,
    )?;
    println!(
        "frps{} 已安全安装到：{}",
        ORANGE_FRPS_VERSION,
        target.display()
    );
    Ok(target.display().to_string())
}

fn run_command_best_effort(program: &str, args: &[&str]) {
    let _ = std::process::Command::new(program).args(args).status();
}

fn remove_path_if_exists(path: &Path) -> Result<()> {
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn owned_frps_matches() -> bool {
    let Ok(marker) = fs::read_to_string(frps_owned_marker()) else {
        return false;
    };
    let expected = marker.split_whitespace().next().unwrap_or_default();
    let Ok(bytes) = fs::read(FRPS_INSTALL_PATH) else {
        return false;
    };
    expected == sha256_hex(&bytes)
}

fn command_uninstall(yes: bool) -> Result<()> {
    require_root("卸载服务端")?;
    if !yes && prompt_non_empty("将停止服务并删除 SQLite 数据，确定卸载？输入 YES 确认: ")? != "YES"
    {
        println!("已取消卸载。");
        return Ok(());
    }
    run_command_best_effort("systemctl", &["stop", SERVICE_NAME]);
    if service_is_active() {
        run_command_best_effort(
            "systemctl",
            &["kill", "--kill-who=all", "--signal=SIGKILL", SERVICE_NAME],
        );
        run_command_best_effort("systemctl", &["stop", SERVICE_NAME]);
    }
    if service_is_active() {
        bail!("无法停止 {SERVICE_NAME} 服务，已取消删除文件。请先检查 systemd 状态。");
    }
    run_command_best_effort("systemctl", &["disable", SERVICE_NAME]);
    run_command_best_effort("systemctl", &["reset-failed", SERVICE_NAME]);
    let remove_owned_frps = owned_frps_matches();
    remove_path_if_exists(&systemd_unit())?;
    remove_path_if_exists(&PathBuf::from(format!(
        "/etc/systemd/system/multi-user.target.wants/{SERVICE_NAME}.service"
    )))?;
    run_command_best_effort("systemctl", &["daemon-reload"]);
    remove_path_if_exists(&config_dir())?;
    remove_path_if_exists(Path::new(LOG_DIR))?;
    if remove_owned_frps {
        remove_path_if_exists(Path::new(FRPS_INSTALL_PATH))?;
    } else if Path::new(FRPS_INSTALL_PATH).exists() {
        println!("检测到 frps 不是 Orange FRP 当前安装的文件，已保留。");
    }
    for path in [ORANGE_MENU_PATH, SERVER_INSTALL_PATH] {
        remove_path_if_exists(Path::new(path))?;
    }
    println!("服务端已卸载。");
    Ok(())
}

pub async fn run() -> Result<()> {
    let command = Cli::parse().command;
    if !cfg!(target_os = "linux") {
        bail!("Orange FRP 服务端仅支持 Linux。");
    }
    match command {
        Commands::Init {
            api_bind,
            api_port,
            frps_port,
            frps_binary,
        } => command_init(api_bind, api_port, frps_port, frps_binary),
        Commands::Setup {
            api_bind,
            api_port,
            frps_port,
            frps_binary,
            skip_frps_install,
            force_frps,
        } => command_setup(
            api_bind,
            api_port,
            frps_port,
            frps_binary,
            skip_frps_install,
            force_frps,
        ),
        Commands::Show => command_show(),
        Commands::Menu => command_menu(),
        Commands::AddUser {
            account,
            password,
            traffic_limit_gb,
            speed_limit_mbps,
            tunnel_limit,
        } => command_add_user(
            account,
            password,
            traffic_limit_gb,
            speed_limit_mbps,
            tunnel_limit,
        ),
        Commands::ViewUsers => command_view_users(),
        Commands::DeleteUser => command_delete_user(),
        Commands::ViewTraffic { account } => command_view_traffic(account),
        Commands::SetTrafficLimit { account, gb } => command_set_traffic_limit(account, gb),
        Commands::SetTrafficUsed { account, gb } => command_set_traffic_used(account, gb),
        Commands::SetSpeedLimit { account, mbps } => command_set_speed_limit(account, mbps),
        Commands::SetTunnelLimit { account, limit } => command_set_tunnel_limit(account, limit),
        Commands::CheckUpdate { yes } => command_check_update(yes).map(|_| ()),
        Commands::Serve { api_only } => command_serve(api_only).await,
        Commands::InstallService => command_install_service(),
        Commands::InstallFrps { force } => {
            require_root("安装 frps")?;
            install_frps_binary(force)?;
            Ok(())
        }
        Commands::ChangeAccount => command_change_account(),
        Commands::ChangePassword => command_change_password(),
        Commands::RotateKey { yes } => command_rotate_key(yes),
        Commands::Uninstall { yes } => command_uninstall(yes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> ServerUser {
        ServerUser {
            id: "user-id".into(),
            account: "demo".into(),
            password_hash: hash_password("password").unwrap(),
            password_encrypted: String::new(),
            secret: "abcdefghijklmnopqrstuvwxyz1234567890".into(),
            tunnels: vec![Tunnel {
                backend_port: 20_000,
                ..Tunnel::default()
            }],
            tunnel_limit: 5,
            traffic_limit_bytes: 1024,
            traffic_used_bytes: 0,
            speed_limit_mbps: 20,
            traffic_by_proxy: HashMap::new(),
            created_at: 1,
            updated_at: 1,
        }
    }

    fn test_config() -> ServerConfig {
        ServerConfig {
            revision: 1,
            api_salt: random_salt(),
            api_bind: "127.0.0.1".into(),
            api_port: 7631,
            frps_bind_port: 7000,
            frps_token: "token".into(),
            frps_binary: "frps".into(),
            plugin_port: 7632,
            public_bind: "127.0.0.1".into(),
            users: vec![test_user()],
            created_at: 1,
            updated_at: 1,
        }
    }

    async fn response_json(response: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn plugin_rejects_unregistered_proxy() {
        let config = test_config();
        let response = plugin_proxy_response(
            &config,
            "demo",
            &config.users[0].secret,
            "unknown",
            "tcp",
            20_001,
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json(response)
                .await
                .get("reject")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[tokio::test]
    async fn plugin_accepts_only_the_registered_backend_port() {
        let config = test_config();
        let tunnel = &config.users[0].tunnels[0];
        let response = plugin_proxy_response(
            &config,
            "demo",
            &config.users[0].secret,
            &format!("demo.{}", tunnel.proxy_name),
            &tunnel.protocol,
            tunnel.backend_port,
        );
        assert_eq!(
            response_json(response)
                .await
                .get("reject")
                .and_then(Value::as_bool),
            Some(false)
        );

        let wrong_prefix = plugin_proxy_response(
            &config,
            "demo",
            &config.users[0].secret,
            &format!("other.{}", tunnel.proxy_name),
            &tunnel.protocol,
            tunnel.backend_port,
        );
        assert_eq!(
            response_json(wrong_prefix)
                .await
                .get("reject")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn encrypted_request_is_bound_to_its_operation() {
        let config = test_config();
        let user = &config.users[0];
        let envelope = encrypt_payload(
            &user.secret,
            &config.api_salt,
            json!({
                "op": "usage",
                "account": user.account,
                "password": "password",
                "key": user.secret,
            }),
        )
        .unwrap();
        assert!(decrypt_and_auth(&config, &envelope, "tunnels").is_err());
        assert!(decrypt_and_auth(&config, &envelope, "usage").is_ok());
    }

    #[test]
    fn replay_guard_rejects_duplicate_nonce() {
        let mut guard = ReplayGuard::default();
        assert!(guard.accept("user", "login", "nonce"));
        assert!(!guard.accept("user", "login", "nonce"));
        assert!(guard.accept("user", "usage", "nonce"));
    }

    #[test]
    fn replay_guard_stays_within_memory_limit() {
        let mut guard = ReplayGuard::default();
        for index in 0..(MAX_REPLAY_ENTRIES + 128) {
            assert!(guard.accept("user", "usage", &format!("nonce-{index}")));
        }
        assert_eq!(guard.seen.len(), MAX_REPLAY_ENTRIES);
        assert_eq!(guard.order.len(), MAX_REPLAY_ENTRIES);
    }

    #[test]
    fn rate_limiter_rejects_new_clients_when_cache_is_full() {
        let mut limiter = ApiRateLimiter::default();
        for index in 0..MAX_RATE_LIMIT_CLIENTS {
            let ip = IpAddr::V6(std::net::Ipv6Addr::from((index as u128) + 1));
            assert!(limiter.allow(ip, 1.0));
        }
        assert!(!limiter.allow(IpAddr::V6(std::net::Ipv6Addr::from(u128::MAX)), 1.0));
        assert_eq!(limiter.clients.len(), MAX_RATE_LIMIT_CLIENTS);
    }

    #[test]
    fn numeric_account_is_selected_before_numeric_index() {
        let mut config = test_config();
        config.users[0].account = "1".into();
        assert_eq!(
            config.users.iter().position(|user| user.account == "1"),
            Some(0)
        );
    }

    #[test]
    fn rejects_tunnels_above_user_limit() {
        let mut config = test_config();
        config.users[0].tunnel_limit = 1;
        let mut tunnels = config.users[0].tunnels.clone();
        tunnels.push(tunnels[0].clone());

        let error = normalize_user_tunnels(&config, 0, &tunnels).unwrap_err();
        assert_eq!(error.to_string(), "超出隧道数量限制：最多可创建 1 条隧道。");
    }

    #[test]
    fn allows_reducing_existing_tunnels_toward_a_lower_limit() {
        let mut config = test_config();
        let mut second = config.users[0].tunnels[0].clone();
        second.id = "second".into();
        second.proxy_name = "orange_second".into();
        second.protocol = "TCP".into();
        second.name = "Second".into();
        second.remark = "test".into();
        second.local_ip = "127.0.0.1".into();
        second.local_port = 25_566;
        second.remote_port = 25_566;
        second.backend_port = 20_001;
        config.users[0].tunnels.push(second.clone());
        config.users[0].tunnel_limit = 0;

        let remaining = vec![second];
        let normalized = normalize_user_tunnels(&config, 0, &remaining).unwrap();
        assert_eq!(normalized.len(), 1);
    }

    #[test]
    fn parses_server_update_manifest_and_normalizes_digest() {
        let (version, digest) = parse_server_update_manifest(
            br#"{"version":"v1.1.4","installer_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","notes":"future-compatible"}"#,
        )
        .unwrap();
        assert_eq!(version, Version::new(1, 1, 4));
        assert_eq!(digest, "a".repeat(64));
    }

    #[test]
    fn rejects_invalid_update_installer_digest() {
        let error = parse_server_update_manifest(
            br#"{"version":"1.1.4","installer_sha256":"not-a-digest"}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("SHA-256"));
    }

    #[test]
    fn parses_server_binary_version_output() {
        let version = parse_server_version_output(b"frp-game-server 1.1.4\n").unwrap();
        assert_eq!(version, Version::new(1, 1, 4));
    }
}
