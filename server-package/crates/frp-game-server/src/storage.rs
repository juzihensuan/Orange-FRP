use anyhow::{bail, Context, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::Engine;
use frp_game_common::{
    decrypt_stored_text, encrypt_stored_text, normalize_tunnels, proxy_name_for, Tunnel,
    DEFAULT_TUNNEL_LIMIT, MAX_TUNNEL_LIMIT,
};
use rand::rngs::OsRng;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

pub const DEFAULT_PLUGIN_PORT: u16 = 7632;
pub const DEFAULT_PUBLIC_BIND: &str = "0.0.0.0";
pub const BACKEND_PORT_START: u16 = 20_000;
pub const BACKEND_PORT_END: u16 = 59_999;
pub const MAX_TUNNELS_PER_USER: usize = MAX_TUNNEL_LIMIT as usize;
const SCHEMA_VERSION: i64 = 3;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub revision: i64,
    pub api_salt: String,
    pub api_bind: String,
    pub api_port: u16,
    pub frps_bind_port: u16,
    pub frps_token: String,
    pub frps_binary: String,
    pub plugin_port: u16,
    pub public_bind: String,
    pub users: Vec<ServerUser>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct ServerUser {
    pub id: String,
    pub account: String,
    pub password_hash: String,
    pub password_encrypted: String,
    pub secret: String,
    pub tunnels: Vec<Tunnel>,
    pub tunnel_limit: u32,
    pub traffic_limit_bytes: u64,
    pub traffic_used_bytes: u64,
    pub speed_limit_mbps: u32,
    pub traffic_by_proxy: HashMap<String, ProxyTrafficRecord>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ProxyTrafficRecord {
    pub protocol: String,
    pub remote_port: u16,
    pub traffic_in_bytes: u64,
    pub traffic_out_bytes: u64,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct Storage {
    path: PathBuf,
}

impl Storage {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn legacy_config_path(&self) -> PathBuf {
        self.path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("config.json")
    }

    pub fn initialize(&self) -> Result<()> {
        self.prepare_parent()?;
        let mut connection = self.open()?;
        create_schema(&mut connection)?;
        if settings_exist(&connection)? {
            let recovered = recover_passwords_from_legacy_backups(
                &mut connection,
                self.path.parent().unwrap_or_else(|| Path::new(".")),
            )?;
            if recovered > 0 {
                println!("已从旧配置备份恢复 {recovered} 个可回显密码。");
            }
            self.secure_file()?;
            return Ok(());
        }

        let legacy_path = self.legacy_config_path();
        if legacy_path.is_file() {
            let mut config = migrate_legacy_config(&legacy_path)?;
            self.save_new(&mut config)?;
            let backup = legacy_path
                .with_file_name(format!("config.json.legacy-backup-{}", config.updated_at));
            fs::rename(&legacy_path, &backup).with_context(|| {
                format!(
                    "SQLite 迁移成功，但旧配置重命名失败：{} -> {}",
                    legacy_path.display(),
                    backup.display()
                )
            })?;
            println!("旧 JSON 配置已迁移到 SQLite：{}", self.path.display());
            println!("旧配置备份：{}", backup.display());
        }
        self.secure_file()?;
        Ok(())
    }

    pub fn is_initialized(&self) -> Result<bool> {
        if !self.path.is_file() {
            return Ok(false);
        }
        let connection = self.open()?;
        settings_exist(&connection)
    }

    pub fn read(&self) -> Result<ServerConfig> {
        self.initialize()?;
        let connection = self.open()?;
        let mut config = connection
            .query_row(
                "SELECT revision, api_salt, api_bind, api_port, frps_bind_port, \
                        frps_token, frps_binary, plugin_port, public_bind, created_at, updated_at \
                 FROM settings WHERE id = 1",
                [],
                |row| {
                    Ok(ServerConfig {
                        revision: row.get(0)?,
                        api_salt: row.get(1)?,
                        api_bind: row.get(2)?,
                        api_port: sql_u16(row.get(3)?)?,
                        frps_bind_port: sql_u16(row.get(4)?)?,
                        frps_token: row.get(5)?,
                        frps_binary: row.get(6)?,
                        plugin_port: sql_u16(row.get(7)?)?,
                        public_bind: row.get(8)?,
                        users: Vec::new(),
                        created_at: row.get(9)?,
                        updated_at: row.get(10)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("尚未初始化，请先运行：sudo frp-game-server setup"))?;

        let mut users = connection.prepare(
            "SELECT id, account, password_hash, password_encrypted, secret, \
                    tunnel_limit, traffic_limit_bytes, traffic_used_bytes, speed_limit_mbps, \
                    created_at, updated_at \
             FROM users ORDER BY account",
        )?;
        let rows = users.query_map([], |row| {
            Ok(ServerUser {
                id: row.get(0)?,
                account: row.get(1)?,
                password_hash: row.get(2)?,
                password_encrypted: row.get(3)?,
                secret: row.get(4)?,
                tunnels: Vec::new(),
                tunnel_limit: sql_u32(row.get(5)?)?,
                traffic_limit_bytes: sql_u64(row.get(6)?)?,
                traffic_used_bytes: sql_u64(row.get(7)?)?,
                speed_limit_mbps: sql_u32(row.get(8)?)?,
                traffic_by_proxy: HashMap::new(),
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        config.users = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(users);

        let index_by_id = config
            .users
            .iter()
            .enumerate()
            .map(|(index, user)| (user.id.clone(), index))
            .collect::<HashMap<_, _>>();

        let mut tunnels = connection.prepare(
            "SELECT id, user_id, proxy_name, protocol, name, remark, local_ip, \
                    local_port, public_port, backend_port \
             FROM tunnels ORDER BY user_id, public_port, protocol",
        )?;
        let rows = tunnels.query_map([], |row| {
            let user_id: String = row.get(1)?;
            Ok((
                user_id,
                Tunnel {
                    id: row.get(0)?,
                    proxy_name: row.get(2)?,
                    protocol: row.get(3)?,
                    name: row.get(4)?,
                    remark: row.get(5)?,
                    local_ip: row.get(6)?,
                    local_port: sql_u16(row.get(7)?)?,
                    remote_port: sql_u16(row.get(8)?)?,
                    backend_port: sql_u16(row.get(9)?)?,
                },
            ))
        })?;
        for row in rows {
            let (user_id, tunnel) = row?;
            if let Some(index) = index_by_id.get(&user_id) {
                config.users[*index].tunnels.push(tunnel);
            }
        }
        drop(tunnels);

        let mut traffic = connection.prepare(
            "SELECT user_id, proxy_name, protocol, public_port, traffic_in_bytes, \
                    traffic_out_bytes, active FROM traffic_records",
        )?;
        let rows = traffic.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                ProxyTrafficRecord {
                    protocol: row.get(2)?,
                    remote_port: sql_u16(row.get(3)?)?,
                    traffic_in_bytes: sql_u64(row.get(4)?)?,
                    traffic_out_bytes: sql_u64(row.get(5)?)?,
                    active: row.get::<_, i64>(6)? != 0,
                },
            ))
        })?;
        for row in rows {
            let (user_id, proxy_name, record) = row?;
            if let Some(index) = index_by_id.get(&user_id) {
                config.users[*index]
                    .traffic_by_proxy
                    .insert(proxy_name, record);
            }
        }
        normalize_loaded_config(&mut config)?;
        Ok(config)
    }

    pub fn save(&self, config: &mut ServerConfig) -> Result<()> {
        self.initialize()?;
        normalize_loaded_config(config)?;
        let mut connection = self.open()?;
        let transaction = connection.transaction()?;
        let current_revision: i64 =
            transaction.query_row("SELECT revision FROM settings WHERE id = 1", [], |row| {
                row.get(0)
            })?;
        if current_revision != config.revision {
            bail!(
                "SQLite 配置已被其他进程更新（当前版本 {current_revision}，内存版本 {}），请重试。",
                config.revision
            );
        }
        config.revision = current_revision.saturating_add(1);
        write_snapshot(&transaction, config)?;
        transaction.commit()?;
        self.secure_file()?;
        Ok(())
    }

    pub fn create(&self, config: &mut ServerConfig) -> Result<()> {
        if self.is_initialized()? {
            bail!("SQLite 服务端已经初始化。");
        }
        self.save_new(config)
    }

    fn save_new(&self, config: &mut ServerConfig) -> Result<()> {
        normalize_loaded_config(config)?;
        let mut connection = self.open()?;
        create_schema(&mut connection)?;
        let transaction = connection.transaction()?;
        config.revision = 1;
        write_snapshot(&transaction, config)?;
        transaction.commit()?;
        self.secure_file()?;
        Ok(())
    }

    fn prepare_parent(&self) -> Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn secure_file(&self) -> Result<()> {
        #[cfg(unix)]
        if self.path.exists() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn open(&self) -> Result<Connection> {
        self.prepare_parent()?;
        let connection = Connection::open(&self.path)
            .with_context(|| format!("无法打开 SQLite 数据库：{}", self.path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        Ok(connection)
    }
}

pub fn hash_password(password: &str) -> Result<String> {
    if password.is_empty() {
        bail!("密码不能为空。");
    }
    let salt = SaltString::generate(&mut OsRng);
    let result = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("密码哈希失败：{error}"));
    release_unused_allocator_pages();
    result
}

pub fn verify_password(password_hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(password_hash) else {
        return false;
    };
    let verified = Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok();
    release_unused_allocator_pages();
    verified
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn release_unused_allocator_pages() {
    unsafe extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }

    // SAFETY: glibc documents malloc_trim as thread-safe; zero requests maximal trimming.
    let _ = unsafe { malloc_trim(0) };
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn release_unused_allocator_pages() {}

pub fn encrypt_user_password(api_salt: &str, secret: &str, password: &str) -> Result<String> {
    if password.is_empty() {
        bail!("密码不能为空。");
    }
    encrypt_stored_text(secret, api_salt, password)
        .map_err(anyhow::Error::new)
        .context("加密用户密码失败")
}

pub fn decrypt_user_password(
    api_salt: &str,
    secret: &str,
    password_encrypted: &str,
) -> Result<Option<String>> {
    if password_encrypted.trim().is_empty() {
        return Ok(None);
    }
    decrypt_stored_text(secret, api_salt, password_encrypted)
        .map(Some)
        .map_err(anyhow::Error::new)
        .context("解密用户密码失败")
}

pub fn new_user_id() -> String {
    Uuid::new_v4().simple().to_string()[..16].to_string()
}

fn create_schema(connection: &mut Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            revision INTEGER NOT NULL,
            api_salt TEXT NOT NULL,
            api_bind TEXT NOT NULL,
            api_port INTEGER NOT NULL,
            frps_bind_port INTEGER NOT NULL,
            frps_token TEXT NOT NULL,
            frps_binary TEXT NOT NULL,
            plugin_port INTEGER NOT NULL,
            public_bind TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            account TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            password_encrypted TEXT NOT NULL,
            secret TEXT NOT NULL UNIQUE,
            tunnel_limit INTEGER NOT NULL,
            traffic_limit_bytes INTEGER NOT NULL,
            traffic_used_bytes INTEGER NOT NULL,
            speed_limit_mbps INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tunnels (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            proxy_name TEXT NOT NULL UNIQUE,
            protocol TEXT NOT NULL CHECK (protocol IN ('TCP', 'UDP')),
            name TEXT NOT NULL,
            remark TEXT NOT NULL,
            local_ip TEXT NOT NULL,
            local_port INTEGER NOT NULL,
            public_port INTEGER NOT NULL,
            backend_port INTEGER NOT NULL UNIQUE,
            UNIQUE(protocol, public_port)
        );
        CREATE TABLE IF NOT EXISTS traffic_records (
            proxy_name TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            protocol TEXT NOT NULL,
            public_port INTEGER NOT NULL,
            traffic_in_bytes INTEGER NOT NULL,
            traffic_out_bytes INTEGER NOT NULL,
            active INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tunnels_user ON tunnels(user_id);
        CREATE INDEX IF NOT EXISTS idx_traffic_user ON traffic_records(user_id);",
    )?;
    if !users_has_password_encrypted_column(connection)? {
        connection.execute(
            "ALTER TABLE users ADD COLUMN password_encrypted TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    if !users_has_column(connection, "tunnel_limit")? {
        connection.execute(
            "ALTER TABLE users ADD COLUMN tunnel_limit INTEGER NOT NULL DEFAULT 256",
            [],
        )?;
    }
    connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

fn users_has_password_encrypted_column(connection: &Connection) -> Result<bool> {
    users_has_column(connection, "password_encrypted")
}

fn users_has_column(connection: &Connection, expected: &str) -> Result<bool> {
    let mut statement = connection.prepare("PRAGMA table_info(users)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for column in columns {
        if column? == expected {
            return Ok(true);
        }
    }
    Ok(false)
}

fn settings_exist(connection: &Connection) -> Result<bool> {
    let exists = connection
        .query_row("SELECT 1 FROM settings WHERE id = 1", [], |_| Ok(()))
        .optional()?
        .is_some();
    Ok(exists)
}

fn recover_passwords_from_legacy_backups(
    connection: &mut Connection,
    directory: &Path,
) -> Result<usize> {
    let missing: i64 = connection.query_row(
        "SELECT COUNT(1) FROM users WHERE password_encrypted = ''",
        [],
        |row| row.get(0),
    )?;
    if missing == 0 {
        return Ok(0);
    }

    let mut backup_paths = match fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("config.json.legacy-backup-"))
            })
            .collect::<Vec<_>>(),
        Err(_) => return Ok(0),
    };
    backup_paths.sort_by(|left, right| right.file_name().cmp(&left.file_name()));

    let mut candidates = HashMap::<String, Vec<String>>::new();
    for path in backup_paths {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let users = value
            .get("users")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_else(|| std::slice::from_ref(&value));
        for user in users {
            let Some(account) = user.get("account").and_then(Value::as_str) else {
                continue;
            };
            let Some(password) = user.get("password").and_then(Value::as_str) else {
                continue;
            };
            if !account.is_empty() && !password.is_empty() {
                let passwords = candidates.entry(account.to_string()).or_default();
                if !passwords.iter().any(|candidate| candidate == password) {
                    passwords.push(password.to_string());
                }
            }
        }
    }
    if candidates.is_empty() {
        return Ok(0);
    }

    let transaction = connection.transaction()?;
    let api_salt: String =
        transaction.query_row("SELECT api_salt FROM settings WHERE id = 1", [], |row| {
            row.get(0)
        })?;
    let users = {
        let mut statement = transaction.prepare(
            "SELECT account, password_hash, secret FROM users WHERE password_encrypted = ''",
        )?;
        let users = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        users
    };

    let mut recovered = 0;
    for (account, password_hash, secret) in users {
        let Some(password) = candidates
            .get(&account)
            .and_then(|passwords| {
                passwords
                    .iter()
                    .find(|password| verify_password(&password_hash, password))
            })
            .cloned()
        else {
            continue;
        };
        let encrypted = encrypt_user_password(&api_salt, &secret, &password)?;
        recovered += transaction.execute(
            "UPDATE users SET password_encrypted = ?1 WHERE account = ?2 AND password_encrypted = ''",
            params![encrypted, account],
        )?;
    }
    transaction.commit()?;
    Ok(recovered)
}

fn write_snapshot(transaction: &Transaction<'_>, config: &ServerConfig) -> Result<()> {
    transaction.execute(
        "INSERT INTO settings (
            id, revision, api_salt, api_bind, api_port, frps_bind_port, frps_token,
            frps_binary, plugin_port, public_bind, created_at, updated_at
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(id) DO UPDATE SET
            revision=excluded.revision,
            api_salt=excluded.api_salt,
            api_bind=excluded.api_bind,
            api_port=excluded.api_port,
            frps_bind_port=excluded.frps_bind_port,
            frps_token=excluded.frps_token,
            frps_binary=excluded.frps_binary,
            plugin_port=excluded.plugin_port,
            public_bind=excluded.public_bind,
            created_at=excluded.created_at,
            updated_at=excluded.updated_at",
        params![
            config.revision,
            config.api_salt,
            config.api_bind,
            i64::from(config.api_port),
            i64::from(config.frps_bind_port),
            config.frps_token,
            config.frps_binary,
            i64::from(config.plugin_port),
            config.public_bind,
            config.created_at,
            config.updated_at,
        ],
    )?;

    let current_user_ids = config
        .users
        .iter()
        .map(|user| user.id.clone())
        .collect::<HashSet<_>>();
    let existing_user_ids = query_strings(transaction, "SELECT id FROM users")?;
    for user_id in existing_user_ids {
        if !current_user_ids.contains(&user_id) {
            transaction.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
        }
    }

    let mut current_tunnel_ids = HashSet::new();
    for user in &config.users {
        transaction.execute(
            "INSERT INTO users (
                id, account, password_hash, password_encrypted, secret,
                tunnel_limit, traffic_limit_bytes, traffic_used_bytes,
                speed_limit_mbps, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(id) DO UPDATE SET
                account=excluded.account,
                password_hash=excluded.password_hash,
                password_encrypted=excluded.password_encrypted,
                secret=excluded.secret,
                tunnel_limit=excluded.tunnel_limit,
                traffic_limit_bytes=excluded.traffic_limit_bytes,
                traffic_used_bytes=excluded.traffic_used_bytes,
                speed_limit_mbps=excluded.speed_limit_mbps,
                created_at=excluded.created_at,
                updated_at=excluded.updated_at",
            params![
                user.id,
                user.account,
                user.password_hash,
                user.password_encrypted,
                user.secret,
                i64::from(user.tunnel_limit),
                sql_i64(user.traffic_limit_bytes)?,
                sql_i64(user.traffic_used_bytes)?,
                i64::from(user.speed_limit_mbps),
                user.created_at,
                user.updated_at,
            ],
        )?;

        let active_proxies = user
            .tunnels
            .iter()
            .map(|tunnel| tunnel.proxy_name.clone())
            .collect::<HashSet<_>>();
        for tunnel in &user.tunnels {
            current_tunnel_ids.insert(tunnel.id.clone());
            transaction.execute(
                "INSERT INTO tunnels (
                    id, user_id, proxy_name, protocol, name, remark, local_ip,
                    local_port, public_port, backend_port
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(id) DO UPDATE SET
                    user_id=excluded.user_id,
                    proxy_name=excluded.proxy_name,
                    protocol=excluded.protocol,
                    name=excluded.name,
                    remark=excluded.remark,
                    local_ip=excluded.local_ip,
                    local_port=excluded.local_port,
                    public_port=excluded.public_port,
                    backend_port=excluded.backend_port",
                params![
                    tunnel.id,
                    user.id,
                    tunnel.proxy_name,
                    tunnel.protocol,
                    tunnel.name,
                    tunnel.remark,
                    tunnel.local_ip,
                    i64::from(tunnel.local_port),
                    i64::from(tunnel.remote_port),
                    i64::from(tunnel.backend_port),
                ],
            )?;
        }

        for (proxy_name, record) in &user.traffic_by_proxy {
            transaction.execute(
                "INSERT INTO traffic_records (
                    proxy_name, user_id, protocol, public_port, traffic_in_bytes,
                    traffic_out_bytes, active
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(proxy_name) DO UPDATE SET
                    user_id=excluded.user_id,
                    protocol=excluded.protocol,
                    public_port=excluded.public_port,
                    traffic_in_bytes=excluded.traffic_in_bytes,
                    traffic_out_bytes=excluded.traffic_out_bytes,
                    active=excluded.active",
                params![
                    proxy_name,
                    user.id,
                    record.protocol,
                    i64::from(record.remote_port),
                    sql_i64(record.traffic_in_bytes)?,
                    sql_i64(record.traffic_out_bytes)?,
                    i64::from(active_proxies.contains(proxy_name) || record.active),
                ],
            )?;
        }
    }

    let existing_tunnel_ids = query_strings(transaction, "SELECT id FROM tunnels")?;
    for tunnel_id in existing_tunnel_ids {
        if !current_tunnel_ids.contains(&tunnel_id) {
            let proxy_name: Option<String> = transaction
                .query_row(
                    "SELECT proxy_name FROM tunnels WHERE id = ?1",
                    params![tunnel_id],
                    |row| row.get(0),
                )
                .optional()?;
            transaction.execute("DELETE FROM tunnels WHERE id = ?1", params![tunnel_id])?;
            if let Some(proxy_name) = proxy_name {
                transaction.execute(
                    "UPDATE traffic_records SET active = 0 WHERE proxy_name = ?1",
                    params![proxy_name],
                )?;
            }
        }
    }
    Ok(())
}

fn query_strings(transaction: &Transaction<'_>, sql: &str) -> Result<Vec<String>> {
    let mut statement = transaction.prepare(sql)?;
    let rows = statement.query_map([], |row| row.get(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn normalize_loaded_config(config: &mut ServerConfig) -> Result<()> {
    if config.api_port == 0 || config.frps_bind_port == 0 || config.plugin_port == 0 {
        bail!("服务端端口不能为 0。");
    }
    if config.api_port == config.frps_bind_port
        || config.api_port == config.plugin_port
        || config.frps_bind_port == config.plugin_port
    {
        bail!("认证 API、FRPS 和控制插件端口不能重复。");
    }
    if config.api_bind.trim().is_empty() || config.public_bind.trim().is_empty() {
        bail!("服务端监听地址不能为空。");
    }
    let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(config.api_salt.as_bytes())
        .map_err(|_| anyhow::anyhow!("认证 API 盐值格式不正确。"))?;
    if salt.len() != 32
        || config.frps_token.trim().is_empty()
        || config.frps_binary.trim().is_empty()
    {
        bail!("服务端认证参数不完整。");
    }
    let mut accounts = HashSet::new();
    let mut user_ids = HashSet::new();
    let mut secrets = HashSet::new();
    let mut tunnel_ids = HashSet::new();
    let mut proxy_names = HashSet::new();
    let mut public_ports = HashSet::new();
    let mut public_port_numbers = HashSet::new();
    let mut backend_ports = HashSet::new();
    let reserved = [config.api_port, config.frps_bind_port, config.plugin_port];
    let api_salt = config.api_salt.clone();
    for user in &mut config.users {
        user.account = user.account.trim().to_string();
        if user.id.trim().is_empty() {
            user.id = new_user_id();
        }
        if user.account.is_empty() || !accounts.insert(user.account.clone()) {
            bail!("用户账号为空或重复：{}", user.account);
        }
        if !user_ids.insert(user.id.clone()) {
            bail!("用户 ID 重复：{}", user.id);
        }
        if user.password_hash.trim().is_empty() {
            bail!("用户 {} 的密码摘要为空。", user.account);
        }
        if user.secret.len() != 36
            || !user
                .secret
                .chars()
                .all(|character| character.is_ascii_alphanumeric())
            || !secrets.insert(user.secret.clone())
        {
            bail!("用户 {} 的 36 位混合密钥无效或重复。", user.account);
        }
        if !user.password_encrypted.trim().is_empty() {
            decrypt_user_password(&api_salt, &user.secret, &user.password_encrypted)
                .with_context(|| format!("用户 {} 的加密密码无效。", user.account))?;
        }
        if user.tunnel_limit > MAX_TUNNEL_LIMIT {
            bail!(
                "用户 {} 的隧道限制超过最大值 {}。",
                user.account,
                MAX_TUNNEL_LIMIT
            );
        }
        if user.tunnels.len() > MAX_TUNNELS_PER_USER {
            bail!(
                "用户 {} 的隧道数量超过上限 {}。",
                user.account,
                MAX_TUNNELS_PER_USER
            );
        }
        user.tunnels = normalize_tunnels(&user.tunnels)?;
        for tunnel in &mut user.tunnels {
            tunnel.proxy_name = proxy_name_for(&tunnel.id);
            if !tunnel_ids.insert(tunnel.id.clone())
                || !proxy_names.insert(tunnel.proxy_name.clone())
            {
                bail!("隧道 ID 或代理标识重复：{}", tunnel.id);
            }
            if reserved.contains(&tunnel.remote_port) {
                bail!("远程端口 {} 是服务端保留端口。", tunnel.remote_port);
            }
            if !public_ports.insert((tunnel.protocol.clone(), tunnel.remote_port)) {
                bail!(
                    "{} 远程端口 {} 已被占用。",
                    tunnel.protocol,
                    tunnel.remote_port
                );
            }
            public_port_numbers.insert(tunnel.remote_port);
            if tunnel.backend_port == 0
                || reserved.contains(&tunnel.backend_port)
                || !backend_ports.insert(tunnel.backend_port)
            {
                bail!("隧道 {} 的后端端口无效或重复。", tunnel.name);
            }
        }
    }
    if let Some(port) = public_port_numbers
        .intersection(&backend_ports)
        .next()
        .copied()
    {
        bail!("公网端口 {port} 与 FRPS 本机后端端口冲突。");
    }
    config
        .users
        .sort_by(|left, right| left.account.cmp(&right.account));
    Ok(())
}

fn migrate_legacy_config(path: &Path) -> Result<ServerConfig> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("读取旧 JSON 配置失败：{}", path.display()))?;
    let value: Value = serde_json::from_str(&text)?;
    let legacy = if value.get("users").is_some() {
        serde_json::from_value::<LegacyServerConfig>(value)?
    } else {
        let single = serde_json::from_value::<LegacySingleConfig>(value)?;
        LegacyServerConfig {
            api_salt: single.api_salt,
            api_bind: single.api_bind,
            api_port: single.api_port,
            frps_bind_port: single.frps_bind_port,
            frps_token: single.frps_token,
            frps_binary: single.frps_binary,
            users: vec![LegacyUser {
                account: single.account,
                password: single.password,
                secret: single.secret,
                tunnels: single.tunnels,
                tunnel_limit: single.tunnel_limit,
                traffic_limit_bytes: 0,
                traffic_used_bytes: 0,
                speed_limit_mbps: 0,
                traffic_by_proxy: HashMap::new(),
                created_at: single.created_at,
                updated_at: single.updated_at,
            }],
            created_at: single.created_at,
            updated_at: single.updated_at,
        }
    };

    let mut used_ports = HashSet::new();
    used_ports.insert(legacy.api_port);
    used_ports.insert(legacy.frps_bind_port);
    used_ports.insert(DEFAULT_PLUGIN_PORT);
    for user in &legacy.users {
        for tunnel in &user.tunnels {
            used_ports.insert(tunnel.remote_port);
        }
    }

    let api_salt = legacy.api_salt.clone();
    let mut users = Vec::new();
    for legacy_user in legacy.users {
        let mut tunnels = normalize_tunnels(&legacy_user.tunnels)?;
        for tunnel in &mut tunnels {
            tunnel.proxy_name = proxy_name_for(&tunnel.id);
            tunnel.backend_port = allocate_backend_port(&mut used_ports)?;
        }
        let active = tunnels
            .iter()
            .map(|tunnel| tunnel.proxy_name.clone())
            .collect::<HashSet<_>>();
        let traffic_by_proxy = legacy_user
            .traffic_by_proxy
            .into_iter()
            .map(|(name, record)| {
                (
                    name.clone(),
                    ProxyTrafficRecord {
                        protocol: record.protocol,
                        remote_port: record.remote_port,
                        traffic_in_bytes: record.traffic_in_bytes,
                        traffic_out_bytes: record.traffic_out_bytes,
                        active: active.contains(&name),
                    },
                )
            })
            .collect();
        let password_hash = hash_password(&legacy_user.password)?;
        let password_encrypted =
            encrypt_user_password(&api_salt, &legacy_user.secret, &legacy_user.password)?;
        users.push(ServerUser {
            id: new_user_id(),
            account: legacy_user.account.trim().to_string(),
            password_hash,
            password_encrypted,
            secret: legacy_user.secret,
            tunnels,
            tunnel_limit: legacy_user.tunnel_limit,
            traffic_limit_bytes: legacy_user.traffic_limit_bytes,
            traffic_used_bytes: legacy_user.traffic_used_bytes,
            speed_limit_mbps: legacy_user.speed_limit_mbps,
            traffic_by_proxy,
            created_at: legacy_user.created_at,
            updated_at: legacy_user.updated_at,
        });
    }
    Ok(ServerConfig {
        revision: 0,
        api_salt: legacy.api_salt,
        api_bind: legacy.api_bind,
        api_port: legacy.api_port,
        frps_bind_port: legacy.frps_bind_port,
        frps_token: legacy.frps_token,
        frps_binary: legacy.frps_binary,
        plugin_port: DEFAULT_PLUGIN_PORT,
        public_bind: DEFAULT_PUBLIC_BIND.to_string(),
        users,
        created_at: legacy.created_at,
        updated_at: legacy.updated_at,
    })
}

pub fn allocate_backend_port(used_ports: &mut HashSet<u16>) -> Result<u16> {
    for port in BACKEND_PORT_START..=BACKEND_PORT_END {
        if used_ports.insert(port) {
            return Ok(port);
        }
    }
    bail!("没有可用的 FRPS 本机后端端口。")
}

fn sql_i64(value: u64) -> Result<i64> {
    i64::try_from(value).context("流量数值超过 SQLite INTEGER 范围")
}

fn sql_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn sql_u32(value: i64) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn sql_u16(value: i64) -> rusqlite::Result<u16> {
    u16::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

#[derive(Debug, Deserialize)]
struct LegacyServerConfig {
    api_salt: String,
    api_bind: String,
    api_port: u16,
    frps_bind_port: u16,
    frps_token: String,
    frps_binary: String,
    #[serde(default)]
    users: Vec<LegacyUser>,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct LegacyUser {
    account: String,
    password: String,
    secret: String,
    #[serde(default)]
    tunnels: Vec<Tunnel>,
    #[serde(default = "default_legacy_tunnel_limit")]
    tunnel_limit: u32,
    #[serde(default)]
    traffic_limit_bytes: u64,
    #[serde(default)]
    traffic_used_bytes: u64,
    #[serde(default)]
    speed_limit_mbps: u32,
    #[serde(default)]
    traffic_by_proxy: HashMap<String, LegacyTrafficRecord>,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    updated_at: i64,
}

#[derive(Debug, Deserialize, Default)]
struct LegacyTrafficRecord {
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    remote_port: u16,
    #[serde(default)]
    traffic_in_bytes: u64,
    #[serde(default)]
    traffic_out_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct LegacySingleConfig {
    account: String,
    password: String,
    secret: String,
    api_salt: String,
    api_bind: String,
    api_port: u16,
    frps_bind_port: u16,
    frps_token: String,
    frps_binary: String,
    #[serde(default)]
    tunnels: Vec<Tunnel>,
    #[serde(default = "default_legacy_tunnel_limit")]
    tunnel_limit: u32,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    updated_at: i64,
}

fn default_legacy_tunnel_limit() -> u32 {
    DEFAULT_TUNNEL_LIMIT
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_storage() -> Storage {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Storage::new(std::env::temp_dir().join(format!("orange-frp-{suffix}.db")))
    }

    #[test]
    fn stores_normalized_snapshot_and_encrypts_passwords() {
        let storage = temp_storage();
        storage.initialize().unwrap();
        let now = 1_700_000_000;
        let api_salt = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1_u8; 32]);
        let user_secret = "abcdefghijklmnopqrstuvwxyz1234567890".to_string();
        let mut config = ServerConfig {
            revision: 0,
            api_salt: api_salt.clone(),
            api_bind: "127.0.0.1".into(),
            api_port: 7631,
            frps_bind_port: 7000,
            frps_token: "token".into(),
            frps_binary: "/usr/local/bin/frps".into(),
            plugin_port: 7632,
            public_bind: "127.0.0.1".into(),
            users: vec![ServerUser {
                id: new_user_id(),
                account: "demo".into(),
                password_hash: hash_password("secret").unwrap(),
                password_encrypted: encrypt_user_password(&api_salt, &user_secret, "secret")
                    .unwrap(),
                secret: user_secret,
                tunnels: vec![Tunnel {
                    id: "tunnel-1".into(),
                    proxy_name: "orange_tunnel_1".into(),
                    protocol: "TCP".into(),
                    name: "Web".into(),
                    remark: "test".into(),
                    local_ip: "127.0.0.1".into(),
                    local_port: 8080,
                    remote_port: 18_080,
                    backend_port: 20_000,
                }],
                tunnel_limit: 8,
                traffic_limit_bytes: 1024,
                traffic_used_bytes: 12,
                speed_limit_mbps: 20,
                traffic_by_proxy: HashMap::new(),
                created_at: now,
                updated_at: now,
            }],
            created_at: now,
            updated_at: now,
        };
        storage.save_new(&mut config).unwrap();
        let loaded = storage.read().unwrap();
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].tunnel_limit, 8);
        assert_eq!(loaded.users[0].tunnels[0].backend_port, 20_000);
        assert!(verify_password(&loaded.users[0].password_hash, "secret"));
        assert_eq!(
            decrypt_user_password(
                &loaded.api_salt,
                &loaded.users[0].secret,
                &loaded.users[0].password_encrypted,
            )
            .unwrap()
            .as_deref(),
            Some("secret")
        );
        let _ = fs::remove_file(storage.path());
    }

    #[test]
    fn upgrades_existing_users_table_to_schema_v3() {
        let storage = temp_storage();
        let mut connection = Connection::open(storage.path()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    account TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    secret TEXT NOT NULL UNIQUE,
                    traffic_limit_bytes INTEGER NOT NULL,
                    traffic_used_bytes INTEGER NOT NULL,
                    speed_limit_mbps INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                INSERT INTO users VALUES (
                    'legacy-id', 'legacy', 'hash',
                    'abcdefghijklmnopqrstuvwxyz1234567890', 0, 0, 0, 1, 1
                );",
            )
            .unwrap();
        create_schema(&mut connection).unwrap();
        assert!(users_has_password_encrypted_column(&connection).unwrap());
        assert!(users_has_column(&connection, "tunnel_limit").unwrap());
        let encrypted: String = connection
            .query_row(
                "SELECT password_encrypted FROM users WHERE id = 'legacy-id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(encrypted.is_empty());
        let tunnel_limit: i64 = connection
            .query_row(
                "SELECT tunnel_limit FROM users WHERE id = 'legacy-id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tunnel_limit, i64::from(DEFAULT_TUNNEL_LIMIT));
        let schema_version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(schema_version, SCHEMA_VERSION);
        drop(connection);
        let _ = fs::remove_file(storage.path());
    }

    #[test]
    fn recovers_matching_passwords_from_legacy_backup() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("orange-frp-recovery-{suffix}"));
        fs::create_dir_all(&directory).unwrap();
        let storage = Storage::new(directory.join("orange-frp.db"));
        let api_salt = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3_u8; 32]);
        let user_secret = "abcdefghijklmnopqrstuvwxyz1234567890".to_string();
        let now = 1_700_000_000;
        let mut config = ServerConfig {
            revision: 0,
            api_salt: api_salt.clone(),
            api_bind: "127.0.0.1".into(),
            api_port: 7631,
            frps_bind_port: 7000,
            frps_token: "token".into(),
            frps_binary: "/usr/local/bin/frps".into(),
            plugin_port: 7632,
            public_bind: "127.0.0.1".into(),
            users: vec![ServerUser {
                id: new_user_id(),
                account: "recover".into(),
                password_hash: hash_password("current-password").unwrap(),
                password_encrypted: String::new(),
                secret: user_secret,
                tunnels: Vec::new(),
                tunnel_limit: DEFAULT_TUNNEL_LIMIT,
                traffic_limit_bytes: 0,
                traffic_used_bytes: 0,
                speed_limit_mbps: 0,
                traffic_by_proxy: HashMap::new(),
                created_at: now,
                updated_at: now,
            }],
            created_at: now,
            updated_at: now,
        };
        storage.save_new(&mut config).unwrap();
        fs::write(
            directory.join("config.json.legacy-backup-1700000000"),
            serde_json::to_vec(&serde_json::json!({
                "users": [{
                    "account": "recover",
                    "password": "current-password"
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        storage.initialize().unwrap();
        let loaded = storage.read().unwrap();
        assert_eq!(
            decrypt_user_password(
                &loaded.api_salt,
                &loaded.users[0].secret,
                &loaded.users[0].password_encrypted,
            )
            .unwrap()
            .as_deref(),
            Some("current-password")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_stale_revision() {
        let storage = temp_storage();
        let now = 1_700_000_000;
        let mut config = ServerConfig {
            revision: 0,
            api_salt: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1_u8; 32]),
            api_bind: "127.0.0.1".into(),
            api_port: 7631,
            frps_bind_port: 7000,
            frps_token: "token".into(),
            frps_binary: "/usr/local/bin/frps".into(),
            plugin_port: 7632,
            public_bind: "127.0.0.1".into(),
            users: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        storage.save_new(&mut config).unwrap();
        let mut first = storage.read().unwrap();
        let mut stale = first.clone();
        first.updated_at += 1;
        storage.save(&mut first).unwrap();
        stale.updated_at += 2;
        assert!(storage.save(&mut stale).is_err());
        let _ = fs::remove_file(storage.path());
    }

    #[test]
    fn migrates_legacy_json_to_sqlite_and_keeps_backup() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("orange-frp-migration-{suffix}"));
        fs::create_dir_all(&directory).unwrap();
        let legacy = directory.join("config.json");
        fs::write(
            &legacy,
            serde_json::to_vec_pretty(&serde_json::json!({
                "api_salt": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2_u8; 32]),
                "api_bind": "0.0.0.0",
                "api_port": 7631,
                "frps_bind_port": 7000,
                "frps_token": "legacy-token",
                "frps_binary": "/usr/local/bin/frps",
                "users": [{
                    "account": "legacy",
                    "password": "legacy-password",
                    "secret": "abcdefghijklmnopqrstuvwxyz1234567890",
                    "tunnels": [{
                        "id": "legacy-tunnel",
                        "proxy_name": "fg-legacy-tunnel",
                        "protocol": "TCP",
                        "name": "Legacy",
                        "remark": "migration",
                        "local_ip": "127.0.0.1",
                        "local_port": 25565,
                        "remote_port": 23111
                    }],
                    "traffic_limit_bytes": 10737418240_u64,
                    "traffic_used_bytes": 4096,
                    "speed_limit_mbps": 20,
                    "traffic_by_proxy": {},
                    "created_at": 1700000000,
                    "updated_at": 1700000000
                }],
                "created_at": 1700000000,
                "updated_at": 1700000000
            }))
            .unwrap(),
        )
        .unwrap();

        let storage = Storage::new(directory.join("server.db"));
        storage.initialize().unwrap();
        let loaded = storage.read().unwrap();
        assert_eq!(loaded.users.len(), 1);
        assert!(verify_password(
            &loaded.users[0].password_hash,
            "legacy-password"
        ));
        assert_eq!(
            decrypt_user_password(
                &loaded.api_salt,
                &loaded.users[0].secret,
                &loaded.users[0].password_encrypted,
            )
            .unwrap()
            .as_deref(),
            Some("legacy-password")
        );
        assert_ne!(loaded.users[0].tunnels[0].backend_port, 0);
        assert!(!legacy.exists());
        assert!(directory
            .join("config.json.legacy-backup-1700000000")
            .is_file());
        fs::remove_dir_all(directory).unwrap();
    }
}
