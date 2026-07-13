use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::storage::{ProxyTrafficRecord, ServerConfig, Storage};

const COPY_BUFFER_BYTES: usize = 16 * 1024;
const ACCOUNTING_QUEUE_CAPACITY: usize = 4096;
const ACCOUNTING_FLUSH_INTERVAL: Duration = Duration::from_millis(500);
const UDP_SESSION_IDLE: Duration = Duration::from_secs(60);
const MAX_TCP_CONNECTIONS_PER_TUNNEL: usize = 1024;
const MAX_TCP_CONNECTIONS_TOTAL: usize = 4096;
const MAX_UDP_SESSIONS_PER_TUNNEL: usize = 512;
const MAX_UDP_SESSIONS_TOTAL: usize = 1024;
const UDP_SESSION_QUEUE_CAPACITY: usize = 1;

#[derive(Debug, Clone, Copy)]
enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone)]
pub(crate) struct TrafficEvent {
    user_id: String,
    proxy_name: String,
    protocol: String,
    public_port: u16,
    direction: Direction,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TunnelSpec {
    user_id: String,
    proxy_name: String,
    protocol: String,
    public_bind: String,
    public_port: u16,
    backend_port: u16,
}

struct ControllerTask {
    spec: TunnelSpec,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

#[derive(Debug)]
struct GateState {
    limit_bytes: u64,
    used_bytes: u64,
    bytes_per_second: u64,
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
struct UserGate {
    state: Mutex<GateState>,
}

impl UserGate {
    fn new(limit_bytes: u64, used_bytes: u64, speed_limit_mbps: u32) -> Self {
        let bytes_per_second = speed_bytes_per_second(speed_limit_mbps);
        Self {
            state: Mutex::new(GateState {
                limit_bytes,
                used_bytes,
                bytes_per_second,
                tokens: burst_capacity(bytes_per_second) as f64,
                last_refill: Instant::now(),
            }),
        }
    }

    async fn update_limits(&self, limit_bytes: u64, speed_limit_mbps: u32) {
        let mut state = self.state.lock().await;
        state.limit_bytes = limit_bytes;
        let bytes_per_second = speed_bytes_per_second(speed_limit_mbps);
        if state.bytes_per_second != bytes_per_second {
            state.bytes_per_second = bytes_per_second;
            state.tokens = burst_capacity(bytes_per_second) as f64;
            state.last_refill = Instant::now();
        }
    }

    async fn reserve_stream(&self, requested: usize) -> Option<usize> {
        self.reserve(requested, false).await
    }

    async fn reserve_datagram(&self, requested: usize) -> bool {
        self.reserve(requested, true).await == Some(requested)
    }

    async fn reserve(&self, requested: usize, exact: bool) -> Option<usize> {
        if requested == 0 {
            return Some(0);
        }
        loop {
            let wait = {
                let mut state = self.state.lock().await;
                let remaining = if state.limit_bytes == 0 {
                    u64::MAX
                } else {
                    state.limit_bytes.saturating_sub(state.used_bytes)
                };
                if remaining == 0 || (exact && remaining < requested as u64) {
                    return None;
                }
                let desired = requested.min(usize::try_from(remaining).unwrap_or(usize::MAX));
                if state.bytes_per_second == 0 {
                    state.used_bytes = state.used_bytes.saturating_add(desired as u64);
                    return Some(desired);
                }

                refill_tokens(&mut state);
                if state.tokens >= desired as f64 {
                    state.tokens -= desired as f64;
                    state.used_bytes = state.used_bytes.saturating_add(desired as u64);
                    return Some(desired);
                }
                let missing = desired as f64 - state.tokens;
                Duration::from_secs_f64(missing / state.bytes_per_second as f64)
                    .clamp(Duration::from_millis(1), Duration::from_secs(2))
            };
            tokio::time::sleep(wait).await;
        }
    }
}

fn speed_bytes_per_second(speed_limit_mbps: u32) -> u64 {
    u64::from(speed_limit_mbps).saturating_mul(1_000_000) / 8
}

fn burst_capacity(bytes_per_second: u64) -> u64 {
    bytes_per_second.max((COPY_BUFFER_BYTES * 4) as u64)
}

fn refill_tokens(state: &mut GateState) {
    let elapsed = state.last_refill.elapsed().as_secs_f64();
    state.last_refill = Instant::now();
    let capacity = burst_capacity(state.bytes_per_second) as f64;
    state.tokens = (state.tokens + elapsed * state.bytes_per_second as f64).min(capacity);
}

#[derive(Clone)]
pub struct TrafficController {
    tasks: Arc<Mutex<HashMap<String, ControllerTask>>>,
    gates: Arc<RwLock<HashMap<String, Arc<UserGate>>>>,
    events: mpsc::Sender<TrafficEvent>,
    tcp_connections: Arc<Semaphore>,
    udp_sessions: Arc<Semaphore>,
}

impl TrafficController {
    pub fn new(config: &ServerConfig) -> (Self, mpsc::Receiver<TrafficEvent>) {
        let (events, receiver) = mpsc::channel(ACCOUNTING_QUEUE_CAPACITY);
        let gates = config
            .users
            .iter()
            .map(|user| {
                (
                    user.id.clone(),
                    Arc::new(UserGate::new(
                        user.traffic_limit_bytes,
                        user.traffic_used_bytes,
                        user.speed_limit_mbps,
                    )),
                )
            })
            .collect();
        (
            Self {
                tasks: Arc::new(Mutex::new(HashMap::new())),
                gates: Arc::new(RwLock::new(gates)),
                events,
                tcp_connections: Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS_TOTAL)),
                udp_sessions: Arc::new(Semaphore::new(MAX_UDP_SESSIONS_TOTAL)),
            },
            receiver,
        )
    }

    pub async fn reconcile(&self, config: &ServerConfig) -> Result<()> {
        self.reconcile_gates(config).await;
        let desired = config
            .users
            .iter()
            .flat_map(|user| {
                user.tunnels.iter().map(|tunnel| TunnelSpec {
                    user_id: user.id.clone(),
                    proxy_name: tunnel.proxy_name.clone(),
                    protocol: tunnel.protocol.clone(),
                    public_bind: config.public_bind.clone(),
                    public_port: tunnel.remote_port,
                    backend_port: tunnel.backend_port,
                })
            })
            .map(|spec| (spec.proxy_name.clone(), spec))
            .collect::<HashMap<_, _>>();

        let mut stopped = Vec::new();
        {
            let mut tasks = self.tasks.lock().await;
            let existing = tasks.keys().cloned().collect::<Vec<_>>();
            for key in existing {
                let keep = tasks
                    .get(&key)
                    .and_then(|task| desired.get(&key).map(|spec| task.spec == *spec))
                    .unwrap_or(false);
                if !keep {
                    if let Some(task) = tasks.remove(&key) {
                        task.cancel.cancel();
                        stopped.push(task.handle);
                    }
                }
            }
        }
        for handle in stopped {
            let _ = handle.await;
        }

        for (key, spec) in desired {
            if self.tasks.lock().await.contains_key(&key) {
                continue;
            }
            let gate = self
                .gates
                .read()
                .await
                .get(&spec.user_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("未找到用户流量控制器：{}", spec.user_id))?;
            let task = self.start_task(spec.clone(), gate).await?;
            self.tasks.lock().await.insert(key, task);
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        let tasks = {
            let mut tasks = self.tasks.lock().await;
            tasks.drain().map(|(_, task)| task).collect::<Vec<_>>()
        };
        for task in &tasks {
            task.cancel.cancel();
        }
        for task in tasks {
            let _ = task.handle.await;
        }
    }

    async fn reconcile_gates(&self, config: &ServerConfig) {
        let desired_ids = config
            .users
            .iter()
            .map(|user| user.id.clone())
            .collect::<HashSet<_>>();
        let mut gates = self.gates.write().await;
        gates.retain(|user_id, _| desired_ids.contains(user_id));
        for user in &config.users {
            if let Some(gate) = gates.get(&user.id) {
                gate.update_limits(user.traffic_limit_bytes, user.speed_limit_mbps)
                    .await;
            } else {
                gates.insert(
                    user.id.clone(),
                    Arc::new(UserGate::new(
                        user.traffic_limit_bytes,
                        user.traffic_used_bytes,
                        user.speed_limit_mbps,
                    )),
                );
            }
        }
    }

    async fn start_task(&self, spec: TunnelSpec, gate: Arc<UserGate>) -> Result<ControllerTask> {
        let cancel = CancellationToken::new();
        let child_cancel = cancel.clone();
        let events = self.events.clone();
        let handle = match spec.protocol.as_str() {
            "TCP" => {
                let listener = TcpListener::bind((spec.public_bind.as_str(), spec.public_port))
                    .await
                    .with_context(|| {
                        format!(
                            "无法监听 TCP 公网端口 {}:{}",
                            spec.public_bind, spec.public_port
                        )
                    })?;
                let task_spec = spec.clone();
                let tcp_connections = self.tcp_connections.clone();
                tokio::spawn(async move {
                    run_tcp_listener(
                        listener,
                        task_spec,
                        gate,
                        events,
                        tcp_connections,
                        child_cancel,
                    )
                    .await;
                })
            }
            "UDP" => {
                let socket = UdpSocket::bind((spec.public_bind.as_str(), spec.public_port))
                    .await
                    .with_context(|| {
                        format!(
                            "无法监听 UDP 公网端口 {}:{}",
                            spec.public_bind, spec.public_port
                        )
                    })?;
                let task_spec = spec.clone();
                let udp_sessions = self.udp_sessions.clone();
                tokio::spawn(async move {
                    run_udp_listener(socket, task_spec, gate, events, udp_sessions, child_cancel)
                        .await;
                })
            }
            _ => unreachable!("protocol was normalized"),
        };
        Ok(ControllerTask {
            spec,
            cancel,
            handle,
        })
    }
}

async fn run_tcp_listener(
    listener: TcpListener,
    spec: TunnelSpec,
    gate: Arc<UserGate>,
    events: mpsc::Sender<TrafficEvent>,
    global_connections: Arc<Semaphore>,
    cancel: CancellationToken,
) {
    let connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS_PER_TUNNEL));
    loop {
        let accepted = tokio::select! {
            _ = cancel.cancelled() => break,
            result = listener.accept() => result,
        };
        let Ok((public, _peer)) = accepted else {
            continue;
        };
        let Ok(connection_permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let Ok(global_permit) = global_connections.clone().try_acquire_owned() else {
            continue;
        };
        let connection_spec = spec.clone();
        let connection_gate = gate.clone();
        let connection_events = events.clone();
        let connection_cancel = cancel.child_token();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let _global_permit = global_permit;
            let _ = proxy_tcp_connection(
                public,
                connection_spec,
                connection_gate,
                connection_events,
                connection_cancel,
            )
            .await;
        });
    }
}

async fn proxy_tcp_connection(
    public: TcpStream,
    spec: TunnelSpec,
    gate: Arc<UserGate>,
    events: mpsc::Sender<TrafficEvent>,
    cancel: CancellationToken,
) -> io::Result<()> {
    let backend = TcpStream::connect(("127.0.0.1", spec.backend_port)).await?;
    let (public_read, public_write) = public.into_split();
    let (backend_read, backend_write) = backend.into_split();
    let upload = copy_limited(
        public_read,
        backend_write,
        gate.clone(),
        events.clone(),
        spec.clone(),
        Direction::In,
    );
    let download = copy_limited(
        backend_read,
        public_write,
        gate,
        events,
        spec,
        Direction::Out,
    );
    tokio::pin!(upload);
    tokio::pin!(download);
    tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        result = &mut upload => result,
        result = &mut download => result,
    }
}

async fn copy_limited<R, W>(
    mut reader: R,
    mut writer: W,
    gate: Arc<UserGate>,
    events: mpsc::Sender<TrafficEvent>,
    spec: TunnelSpec,
    direction: Direction,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        let mut offset = 0;
        while offset < read {
            let Some(allowed) = gate.reserve_stream(read - offset).await else {
                writer.shutdown().await?;
                return Ok(());
            };
            writer.write_all(&buffer[offset..offset + allowed]).await?;
            offset += allowed;
            let _ = events
                .send(TrafficEvent {
                    user_id: spec.user_id.clone(),
                    proxy_name: spec.proxy_name.clone(),
                    protocol: spec.protocol.clone(),
                    public_port: spec.public_port,
                    direction,
                    bytes: allowed as u64,
                })
                .await;
        }
    }
}

async fn run_udp_listener(
    socket: UdpSocket,
    spec: TunnelSpec,
    gate: Arc<UserGate>,
    events: mpsc::Sender<TrafficEvent>,
    global_sessions: Arc<Semaphore>,
    cancel: CancellationToken,
) {
    let public = Arc::new(socket);
    let sessions = Arc::new(Mutex::new(
        HashMap::<SocketAddr, mpsc::Sender<Vec<u8>>>::new(),
    ));
    let mut buffer = vec![0_u8; 65_535];
    loop {
        let received = tokio::select! {
            _ = cancel.cancelled() => break,
            result = public.recv_from(&mut buffer) => result,
        };
        let Ok((size, peer)) = received else {
            continue;
        };
        let mut data = buffer[..size].to_vec();
        let existing = sessions.lock().await.get(&peer).cloned();
        if let Some(sender) = existing {
            data = match sender.try_send(data) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                Err(mpsc::error::TrySendError::Closed(data)) => data,
            };
            sessions.lock().await.remove(&peer);
        }
        if sessions.lock().await.len() >= MAX_UDP_SESSIONS_PER_TUNNEL {
            continue;
        }
        let Ok(session_permit) = global_sessions.clone().try_acquire_owned() else {
            continue;
        };

        let (sender, receiver) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
        if sender.try_send(data).is_err() {
            continue;
        }
        let cleanup_sender = sender.clone();
        sessions.lock().await.insert(peer, sender);
        let session_map = sessions.clone();
        let session_public = public.clone();
        let session_spec = spec.clone();
        let session_gate = gate.clone();
        let session_events = events.clone();
        let session_cancel = cancel.child_token();
        tokio::spawn(async move {
            let _session_permit = session_permit;
            run_udp_session(
                session_public,
                peer,
                receiver,
                session_spec,
                session_gate,
                session_events,
                session_cancel,
            )
            .await;
            let mut sessions = session_map.lock().await;
            let is_current = sessions
                .get(&peer)
                .map(|sender| sender.same_channel(&cleanup_sender))
                .unwrap_or(false);
            if is_current {
                sessions.remove(&peer);
            }
        });
    }
}

async fn run_udp_session(
    public: Arc<UdpSocket>,
    peer: SocketAddr,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    spec: TunnelSpec,
    gate: Arc<UserGate>,
    events: mpsc::Sender<TrafficEvent>,
    cancel: CancellationToken,
) {
    let Ok(backend) = UdpSocket::bind(("0.0.0.0", 0)).await else {
        return;
    };
    if backend
        .connect(("127.0.0.1", spec.backend_port))
        .await
        .is_err()
    {
        return;
    }
    let mut response = vec![0_u8; 65_535];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(UDP_SESSION_IDLE) => break,
            packet = inbound.recv() => {
                let Some(packet) = packet else { break; };
                if !gate.reserve_datagram(packet.len()).await {
                    break;
                }
                if backend.send(&packet).await.is_err() {
                    break;
                }
                let _ = events.send(TrafficEvent {
                    user_id: spec.user_id.clone(),
                    proxy_name: spec.proxy_name.clone(),
                    protocol: spec.protocol.clone(),
                    public_port: spec.public_port,
                    direction: Direction::In,
                    bytes: packet.len() as u64,
                }).await;
            }
            result = backend.recv(&mut response) => {
                let Ok(size) = result else { break; };
                if !gate.reserve_datagram(size).await {
                    break;
                }
                if public.send_to(&response[..size], peer).await.is_err() {
                    break;
                }
                let _ = events.send(TrafficEvent {
                    user_id: spec.user_id.clone(),
                    proxy_name: spec.proxy_name.clone(),
                    protocol: spec.protocol.clone(),
                    public_port: spec.public_port,
                    direction: Direction::Out,
                    bytes: size as u64,
                }).await;
            }
        }
    }
}

#[derive(Default)]
struct PendingTraffic {
    total: u64,
    per_proxy: HashMap<(String, String), PendingProxyTraffic>,
}

#[derive(Debug, Clone)]
struct PendingProxyTraffic {
    protocol: String,
    public_port: u16,
    traffic_in: u64,
    traffic_out: u64,
}

pub fn spawn_accounting_task(
    storage: Storage,
    config: Arc<RwLock<ServerConfig>>,
    mut receiver: mpsc::Receiver<TrafficEvent>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut pending = HashMap::<String, PendingTraffic>::new();
        let mut interval = tokio::time::interval(ACCOUNTING_FLUSH_INTERVAL);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    drain_events(&mut receiver, &mut pending);
                    let _ = flush_pending(&storage, &config, &pending).await;
                    break;
                }
                Some(event) = receiver.recv() => add_event(&mut pending, event),
                _ = interval.tick() => {
                    drain_events(&mut receiver, &mut pending);
                    if flush_pending(&storage, &config, &pending).await.is_ok() {
                        pending.clear();
                    }
                }
            }
        }
    })
}

fn drain_events(
    receiver: &mut mpsc::Receiver<TrafficEvent>,
    pending: &mut HashMap<String, PendingTraffic>,
) {
    while let Ok(event) = receiver.try_recv() {
        add_event(pending, event);
    }
}

fn add_event(pending: &mut HashMap<String, PendingTraffic>, event: TrafficEvent) {
    let user = pending.entry(event.user_id).or_default();
    user.total = user.total.saturating_add(event.bytes);
    let proxy = user
        .per_proxy
        .entry((event.proxy_name, event.protocol.clone()))
        .or_insert(PendingProxyTraffic {
            protocol: event.protocol,
            public_port: event.public_port,
            traffic_in: 0,
            traffic_out: 0,
        });
    match event.direction {
        Direction::In => proxy.traffic_in = proxy.traffic_in.saturating_add(event.bytes),
        Direction::Out => proxy.traffic_out = proxy.traffic_out.saturating_add(event.bytes),
    }
}

async fn flush_pending(
    storage: &Storage,
    config: &Arc<RwLock<ServerConfig>>,
    pending: &HashMap<String, PendingTraffic>,
) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let mut guard = config.write().await;
    let mut candidate = guard.clone();
    for user in &mut candidate.users {
        let Some(update) = pending.get(&user.id) else {
            continue;
        };
        user.traffic_used_bytes = user.traffic_used_bytes.saturating_add(update.total);
        for ((proxy_name, _protocol), proxy) in &update.per_proxy {
            let record = user
                .traffic_by_proxy
                .entry(proxy_name.clone())
                .or_insert_with(|| ProxyTrafficRecord {
                    protocol: proxy.protocol.clone(),
                    remote_port: proxy.public_port,
                    active: true,
                    ..ProxyTrafficRecord::default()
                });
            record.protocol = proxy.protocol.clone();
            record.remote_port = proxy.public_port;
            record.traffic_in_bytes = record.traffic_in_bytes.saturating_add(proxy.traffic_in);
            record.traffic_out_bytes = record.traffic_out_bytes.saturating_add(proxy.traffic_out);
            record.active = true;
        }
    }
    storage.save(&mut candidate)?;
    *guard = candidate;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn aggregate_gate_enforces_quota() {
        let gate = UserGate::new(10, 0, 0);
        assert_eq!(gate.reserve_stream(7).await, Some(7));
        assert_eq!(gate.reserve_stream(7).await, Some(3));
        assert_eq!(gate.reserve_stream(1).await, None);
    }

    #[tokio::test]
    async fn datagram_is_rejected_when_quota_cannot_fit_whole_packet() {
        let gate = UserGate::new(5, 0, 0);
        assert!(!gate.reserve_datagram(6).await);
        assert!(gate.reserve_datagram(5).await);
        assert!(!gate.reserve_datagram(1).await);
    }
}
