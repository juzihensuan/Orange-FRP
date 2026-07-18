# Orange FRP Linux 服务端包

此目录可以独立上传到 Linux，只包含安装脚本、服务端和共享协议源码，不包含 Windows 客户端。

```text
server-package/
  install.sh
  Cargo.toml
  Cargo.lock
  crates/frp-game-common/
  crates/frp-game-server/
```

一键下载安装：

```bash
curl -fsSL https://raw.githubusercontent.com/juzihensuan/Orange-FRP/main/install-server.sh | sudo bash
```

手动安装：

```bash
cd /path/to/server-package
sudo bash install.sh
```

非交互直接安装：

```bash
sudo bash install.sh --install
```

脚本会安装系统依赖和 Rust、执行 `cargo build --release --locked`、校验并安装 FRPS 0.69.1、创建 `frp-game.service` 并设置开机自启。重复安装会停止旧服务、替换程序并重新启动，不会继续运行旧二进制。

安装完成后运行：

```bash
orange
```

菜单支持用户增删查、端口与上下行流量查看、总流量和剩余流量查看、流量限制、已用流量、Mbps 限速和隧道数量限制修改，以及完整卸载。

服务端使用 `/etc/frp-game/orange-frp.db` 保存 SQLite 数据。旧版 `config.json` 会自动迁移并保留带时间戳的备份，明文密码会转换为 Argon2id 摘要。

公网 TCP/UDP 监听、聚合限速、流量配额和计量由 Orange FRP 自研控制器负责。FRPS 只监听回环后端端口，并通过 HTTP 插件校验每个用户的账号、36 位密钥、代理标识、协议和后端端口。

创建测试账号示例：

```bash
sudo frp-game-server add-user \
  --account test01 \
  --password 'StrongPassword' \
  --traffic-limit-gb 10 \
  --speed-limit-mbps 20 \
  --tunnel-limit 5
```

新建用户默认可创建 5 条隧道，`--tunnel-limit 0` 表示禁止创建，最大值为 256。修改已有用户：

```bash
sudo frp-game-server set-tunnel-limit --account test01 --limit 10
```

卸载：

```bash
sudo frp-game-server uninstall --yes
```

卸载只终止 `frp-game` systemd cgroup。FRPS 文件只有在哈希与 Orange FRP 所有权标记一致时才会删除，不会影响系统中的其他 FRP 实例。
