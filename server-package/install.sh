#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Orange FRP服务端"
SERVER_BIN="/usr/local/bin/frp-game-server"
ORANGE_BIN="/usr/local/bin/orange"

RED="\033[31;1m"
GREEN="\033[32;1m"
YELLOW="\033[33;1m"
CYAN="\033[36;1m"
MAGENTA="\033[35;1m"
RESET="\033[0m"

title() {
  clear || true
  echo -e "${MAGENTA}======================================${RESET}"
  echo -e "${MAGENTA}          ${APP_NAME}${RESET}"
  echo -e "${MAGENTA}======================================${RESET}"
}

warn_root() {
  echo -e "${YELLOW}高权限操作警告：安装会写入 /usr/local/bin、/etc/frp-game 和 systemd。${RESET}"
  echo -e "${YELLOW}请确认你正在自己的 Linux 服务器上执行此脚本。${RESET}"
  echo
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}请使用 root 权限运行：sudo bash install.sh${RESET}"
    exit 1
  fi
}

install_dependencies() {
  echo -e "${CYAN}正在安装系统依赖...${RESET}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      ca-certificates curl build-essential pkg-config
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl gcc gcc-c++ make pkgconf-pkg-config
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl gcc gcc-c++ make pkgconfig
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ca-certificates curl base-devel pkgconf
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install ca-certificates curl gcc gcc-c++ make pkg-config
  else
    echo -e "${RED}未识别包管理器，请先手动安装 curl、CA 证书和 C/C++ 编译工具链。${RESET}"
    exit 1
  fi
}

install_rust_if_needed() {
  if command -v cargo >/dev/null 2>&1; then
    echo -e "${GREEN}已检测到 Rust/Cargo。${RESET}"
    return
  fi

  echo -e "${CYAN}未检测到 Rust，正在通过 rustup 自动安装...${RESET}"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  export PATH="${HOME}/.cargo/bin:${PATH}"
  if [ -f "${HOME}/.cargo/env" ]; then
    # shellcheck disable=SC1090
    . "${HOME}/.cargo/env"
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    echo -e "${RED}Rust 安装后仍未找到 cargo，请重新打开终端后再试。${RESET}"
    exit 1
  fi
}

install_orange_command() {
  cat > "${ORANGE_BIN}" <<'EOF'
#!/usr/bin/env bash
if [ "$(id -u)" -ne 0 ]; then
  exec sudo /usr/local/bin/frp-game-server menu "$@"
fi
exec /usr/local/bin/frp-game-server menu "$@"
EOF
  chmod 0755 "${ORANGE_BIN}"
}

is_bundle_root() {
  local dir="$1"
  [ -f "${dir}/Cargo.toml" ] && [ -d "${dir}/crates/frp-game-server" ] && [ -d "${dir}/crates/frp-game-common" ]
}

walk_up_for_bundle_root() {
  local dir="$1"
  while [ -n "${dir}" ] && [ "${dir}" != "/" ]; do
    if is_bundle_root "${dir}"; then
      echo "${dir}"
      return 0
    fi
    dir="$(dirname -- "${dir}")"
  done
  return 1
}

find_bundle_root() {
  local script_dir="$1"
  local root=""

  if [ -n "${ORANGE_FRP_ROOT:-}" ]; then
    root="$(cd -- "${ORANGE_FRP_ROOT}" 2>/dev/null && pwd)" || true
    if [ -n "${root}" ] && is_bundle_root "${root}"; then
      echo "${root}"
      return 0
    fi
  fi

  if root="$(walk_up_for_bundle_root "${script_dir}")"; then
    echo "${root}"
    return 0
  fi

  if root="$(walk_up_for_bundle_root "$(pwd)")"; then
    echo "${root}"
    return 0
  fi

  return 1
}

require_bundle_root() {
  local script_dir="$1"
  local root
  if root="$(find_bundle_root "${script_dir}")"; then
    echo "${root}"
    return 0
  fi

  echo -e "${RED}未找到 Orange FRP 服务端发布包目录。${RESET}"
  echo "install.sh 需要和 Cargo.toml、crates/frp-game-server、crates/frp-game-common 放在同一个发布包内。"
  echo
  echo "正确示例："
  echo "  cd /path/to/server-package"
  echo "  sudo bash install.sh"
  exit 1
}

install_server() {
  local script_dir root_dir
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  root_dir="$(require_bundle_root "${script_dir}")"

  install_dependencies
  install_rust_if_needed

  echo -e "${CYAN}正在编译 Rust 服务端...${RESET}"
  cd "${root_dir}"
  cargo build --release --locked -p frp-game-server

  echo -e "${CYAN}正在安装服务端命令...${RESET}"
  local service_was_active=0
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet frp-game; then
    service_was_active=1
    systemctl stop frp-game
  fi
  if ! install -m 0755 "${root_dir}/target/release/frp-game-server" "${SERVER_BIN}"; then
    if [ "${service_was_active}" -eq 1 ]; then systemctl start frp-game || true; fi
    return 1
  fi
  install_orange_command

  echo -e "${CYAN}正在下载 frps0.69.1 并注册开机自启服务...${RESET}"
  if ! "${SERVER_BIN}" setup --force-frps; then
    if [ "${service_was_active}" -eq 1 ]; then systemctl start frp-game || true; fi
    return 1
  fi

  echo
  echo -e "${GREEN}安装完成。${RESET}"
  echo -e "${GREEN}以后输入 ${CYAN}orange${GREEN} 即可唤出菜单栏。${RESET}"
}

main_menu() {
  while true; do
    title
    warn_root
    echo "1. 安装服务端"
    echo "2. 退出安装"
    echo
    read -r -p "请选择操作: " choice
    case "${choice}" in
      1)
        install_server
        echo
        read -r -p "按 Enter 退出安装脚本..."
        return
        ;;
      2)
        echo "已退出安装。"
        return
        ;;
      *)
        echo -e "${RED}无效选择，请重新输入。${RESET}"
        sleep 1
        ;;
    esac
  done
}

main() {
  require_root
  case "${1:-}" in
    --install)
      install_server
      ;;
    --help|-h)
      echo "用法：sudo bash install.sh [--install]"
      echo "不带参数时打开交互式安装菜单，--install 直接开始安装。"
      ;;
    "")
      main_menu
      ;;
    *)
      echo -e "${RED}未知参数：$1${RESET}" >&2
      echo "用法：sudo bash install.sh [--install]" >&2
      exit 2
      ;;
  esac
}

main "$@"
