# Orange FRP

一个面向游戏联机的便携式 FRP 客户端与 Linux 服务端管理工具。

## Linux 服务端一键安装

目前自动安装的 FRPS 适用于 Linux x86_64。使用 root 权限执行：

```bash
curl -fsSL https://raw.githubusercontent.com/juzihensuan/Orange-FRP/main/install-server.sh | sudo bash
```

脚本会自动下载服务端源码、安装编译依赖与 Rust、构建 Orange FRP 服务端、校验并安装 FRPS 0.69.1，以及注册并启动 systemd 服务。

安装完成后打开管理菜单：

```bash
orange
```

服务端支持用户管理、隧道端口记录、流量统计、流量配额、Mbps 限速和完整卸载。配置与用户数据保存在 SQLite 数据库 `/etc/frp-game/orange-frp.db`。

## 手动安装

```bash
git clone https://github.com/juzihensuan/Orange-FRP.git
cd Orange-FRP/server-package
sudo bash install.sh
```

服务端源码与详细说明位于 [`server-package/`](server-package/README.md)。
