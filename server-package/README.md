# Orange FRP Linux 服务端包

此目录可以独立上传到 Linux，只包含安装脚本、服务端和共享协议源码，不包含 Windows 客户端。默认安装直接下载经过 SHA-256 校验的静态服务端，不需要 Rust 或系统编译工具链。

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

默认脚本只需要 `curl`、`sha256sum`、`coreutils` 和 systemd。它会下载约 6.6 MiB 的 Linux x86_64 静态服务端，验证固定 SHA-256 和版本号，再校验并安装 FRPS 0.69.1、创建 `frp-game.service` 并设置开机自启。重复安装会复用版本正确的 FRPS，不会重新下载 Rust 或编译依赖。

只有开发或无法使用预编译程序时才从源码构建：

```bash
sudo bash install.sh --build-from-source
```

该模式才会安装 Rust、GCC、Make 和 pkg-config，并执行锁定依赖的 Release 构建。

安装完成后运行：

```bash
orange
```

当前服务端版本为 `1.1.4`，与客户端版本同步。菜单标题显示为 `Orange FRP 菜单栏`，支持用户增删查、端口与上下行流量查看、总流量和剩余流量查看、流量限制、已用流量、Mbps 限速、隧道数量限制修改、手动检查更新和完整卸载。

从旧服务端 `2.1.0` 切换到 `1.1.4` 时需手动执行一次一键安装命令。旧版更新器会把 `1.1.4` 判断为较低版本；手动安装只替换程序和服务配置，不会删除 SQLite 用户、隧道或流量数据。

查看版本或直接检查更新：

```bash
frp-game-server --version
sudo frp-game-server check-update
sudo frp-game-server check-update --yes
```

更新程序从 GitHub `main` 分支读取 `server-package/update.json`，并在执行一键安装脚本前验证下载大小和 SHA-256。安装器还会再次验证二级安装脚本和静态服务端二进制；重复安装会保留 `/etc/frp-game/orange-frp.db`。

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
