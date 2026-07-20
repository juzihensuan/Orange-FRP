# Orange FRP

一个面向游戏联机的便携式 FRP 客户端与 Linux 服务端管理工具。

## Linux 服务端一键安装

目前自动安装的 FRPS 适用于 Linux x86_64。使用 root 权限执行：

```bash
curl -fsSL https://raw.githubusercontent.com/juzihensuan/Orange-FRP/main/install-server.sh | sudo bash
```

脚本会下载并校验约 6.6 MiB 的预编译静态服务端，不再下载源码、Rust、GCC、Make 或 pkg-config。首次安装仍会校验并下载 FRPS 0.69.1，然后注册并启动 systemd 服务。

从旧服务端 `2.1.0` 切换到与客户端同步的 `1.1.4` 时，请手动执行一次上面的一键安装命令。旧版按语义版本比较会把 `1.1.4` 视为较低版本，无法通过旧菜单自动完成这次版本归一；安装过程会保留 SQLite 数据库。

安装完成后打开管理菜单：

```bash
orange
```

服务端支持用户管理、每用户隧道数量限制、隧道端口记录、流量统计、流量配额、Mbps 限速、菜单手动更新和完整卸载。配置与用户数据保存在 SQLite 数据库 `/etc/frp-game/orange-frp.db`。

## 手动安装

```bash
git clone https://github.com/juzihensuan/Orange-FRP.git
cd Orange-FRP/server-package
sudo bash install.sh
```

服务端源码与详细说明位于 [`server-package/`](server-package/README.md)。

只有需要自行编译时才运行：

```bash
sudo bash install.sh --build-from-source
```
