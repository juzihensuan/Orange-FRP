#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Orange FRP服务端"
SERVER_VERSION="1.1.4"
SERVER_ASSET="frp-game-server1.1.4-linux-amd64"
SERVER_DOWNLOAD_URL="${ORANGE_FRP_SERVER_DOWNLOAD_URL:-https://raw.githubusercontent.com/juzihensuan/Orange-FRP/main/Update/${SERVER_ASSET}}"
SERVER_SHA256="${ORANGE_FRP_SERVER_SHA256:-3d4a38a655859632031985b510851a4b5331f37c796a183e9b94a04be71b19e1}"
SERVER_BIN="${ORANGE_FRP_SERVER_BIN:-/usr/local/bin/frp-game-server}"
ORANGE_BIN="${ORANGE_FRP_ORANGE_BIN:-/usr/local/bin/orange}"
FRPS_BIN="${ORANGE_FRP_FRPS_BIN:-/usr/local/bin/frps}"
SERVICE_NAME="frp-game"
MAX_SERVER_BYTES=$((64 * 1024 * 1024))

RED="\033[31;1m"
GREEN="\033[32;1m"
YELLOW="\033[33;1m"
CYAN="\033[36;1m"
MAGENTA="\033[35;1m"
RESET="\033[0m"

fail() {
  echo -e "${RED}安装失败：$*${RESET}" >&2
  exit 1
}

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

require_platform() {
  [ "$(uname -s)" = "Linux" ] || fail "Orange FRP 服务端仅支持 Linux。"
  case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "当前预编译服务端仅支持 Linux x86_64。" ;;
  esac
  [ "$(id -u)" -eq 0 ] || fail "请使用 root 权限运行：sudo bash install.sh"
  command -v systemctl >/dev/null 2>&1 || fail "当前系统未使用 systemd，无法注册服务。"
  command -v install >/dev/null 2>&1 || fail "缺少 install 命令，请安装 coreutils。"
  command -v mktemp >/dev/null 2>&1 || fail "缺少 mktemp 命令。"
}

install_download_dependencies() {
  if command -v curl >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1; then
    return
  fi

  echo -e "${CYAN}正在安装最小下载依赖...${RESET}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl coreutils
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl coreutils
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl coreutils
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ca-certificates curl coreutils
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install ca-certificates curl coreutils
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache ca-certificates curl coreutils
  else
    fail "缺少 curl/sha256sum，且未识别可用的包管理器。"
  fi
}

sha256_file() {
  local output
  if command -v sha256sum >/dev/null 2>&1; then
    output="$(sha256sum "$1")"
    printf '%s\n' "${output%% *}"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    output="$(shasum -a 256 "$1")"
    printf '%s\n' "${output%% *}"
    return
  fi
  fail "缺少 SHA-256 校验工具。"
}

install_orange_command() {
  local temporary
  temporary="$(mktemp)"
  cat > "${temporary}" <<EOF
#!/usr/bin/env bash
if [ "\$(id -u)" -ne 0 ]; then
  exec sudo "${SERVER_BIN}" menu "\$@"
fi
exec "${SERVER_BIN}" menu "\$@"
EOF
  install -m 0755 "${temporary}" "${ORANGE_BIN}"
  rm -f -- "${temporary}"
}

script_directory() {
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd
}

find_bundle_root() {
  local candidate
  if [ -n "${ORANGE_FRP_ROOT:-}" ]; then
    candidate="$(cd -- "${ORANGE_FRP_ROOT}" 2>/dev/null && pwd)" || true
  else
    candidate="$(script_directory)"
  fi
  if [ -f "${candidate}/Cargo.toml" ] \
    && [ -d "${candidate}/crates/frp-game-server" ] \
    && [ -d "${candidate}/crates/frp-game-common" ]; then
    printf '%s\n' "${candidate}"
    return
  fi
  fail "源码构建需要完整的 server-package 目录。"
}

install_build_dependencies() {
  echo -e "${CYAN}正在安装源码构建依赖...${RESET}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl build-essential pkg-config
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl gcc gcc-c++ make pkgconf-pkg-config
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl gcc gcc-c++ make pkgconfig
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ca-certificates curl base-devel pkgconf
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install ca-certificates curl gcc gcc-c++ make pkg-config
  else
    fail "未识别包管理器，无法安装源码构建依赖。"
  fi
}

install_rust_if_needed() {
  if command -v cargo >/dev/null 2>&1; then
    return
  fi
  echo -e "${CYAN}正在安装最小 Rust 工具链...${RESET}"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  export PATH="${HOME}/.cargo/bin:${PATH}"
  if [ -f "${HOME}/.cargo/env" ]; then
    # shellcheck disable=SC1090
    . "${HOME}/.cargo/env"
  fi
  command -v cargo >/dev/null 2>&1 || fail "Rust 安装后仍未找到 cargo。"
}

build_server_from_source() {
  local root
  root="$(find_bundle_root)"
  install_build_dependencies
  install_rust_if_needed
  echo -e "${CYAN}正在从源码编译服务端...${RESET}"
  (
    cd "${root}"
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
      CARGO_PROFILE_RELEASE_LTO=thin \
      CARGO_PROFILE_RELEASE_PANIC=abort \
      CARGO_PROFILE_RELEASE_STRIP=symbols \
      cargo build --release --locked -p frp-game-server
  )
  SERVER_SOURCE="${root}/target/release/frp-game-server"
}

download_prebuilt_server() {
  local destination="$1"
  local bundled source_size digest version_output
  bundled="$(script_directory)/bin/${SERVER_ASSET}"

  if [ -n "${ORANGE_FRP_SERVER_BINARY:-}" ]; then
    echo -e "${CYAN}正在使用指定的服务端二进制...${RESET}" >&2
    install -m 0755 "${ORANGE_FRP_SERVER_BINARY}" "${destination}"
  elif [ -f "${bundled}" ]; then
    echo -e "${CYAN}正在使用发布包内置的服务端二进制...${RESET}" >&2
    install -m 0755 "${bundled}" "${destination}"
  else
    install_download_dependencies
    echo -e "${CYAN}正在下载 Orange FRP 服务端 v${SERVER_VERSION}...${RESET}" >&2
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
      "${SERVER_DOWNLOAD_URL}" -o "${destination}"
    chmod 0755 "${destination}"
  fi

  source_size="$(wc -c < "${destination}")"
  [ "${source_size}" -gt 0 ] || fail "下载的服务端文件为空。"
  [ "${source_size}" -le "${MAX_SERVER_BYTES}" ] || fail "下载的服务端文件超过大小限制。"
  digest="$(sha256_file "${destination}")"
  [ "${digest}" = "${SERVER_SHA256}" ] || fail "服务端二进制 SHA-256 校验失败，已拒绝安装。"
  version_output="$("${destination}" --version 2>&1)"
  [ "${version_output}" = "frp-game-server ${SERVER_VERSION}" ] \
    || fail "服务端二进制版本不匹配：${version_output}"
  SERVER_SOURCE="${destination}"
}

frps_is_current() {
  local output
  [ -x "${FRPS_BIN}" ] || return 1
  output="$("${FRPS_BIN}" --version 2>&1 || true)"
  printf '%s' "${output}" | grep -q '0\.69\.1'
}

install_server_binary() {
  local source="$1"
  local temporary backup service_was_active=0
  temporary="${SERVER_BIN}.new.$$"
  backup="${SERVER_BIN}.backup.$$"

  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    service_was_active=1
    systemctl stop "${SERVICE_NAME}"
  fi
  if [ -f "${SERVER_BIN}" ]; then
    cp -p -- "${SERVER_BIN}" "${backup}"
  fi

  install -m 0755 "${source}" "${temporary}"
  mv -f -- "${temporary}" "${SERVER_BIN}"
  install_orange_command

  echo -e "${CYAN}正在配置 FRPS 和 systemd 服务...${RESET}"
  if frps_is_current; then
    if ! "${SERVER_BIN}" setup --skip-frps-install --frps-binary "${FRPS_BIN}"; then
      [ -f "${backup}" ] && mv -f -- "${backup}" "${SERVER_BIN}"
      [ "${service_was_active}" -eq 1 ] && systemctl start "${SERVICE_NAME}" || true
      fail "服务端配置失败，已恢复旧程序。"
    fi
  elif ! "${SERVER_BIN}" setup --force-frps; then
    [ -f "${backup}" ] && mv -f -- "${backup}" "${SERVER_BIN}"
    [ "${service_was_active}" -eq 1 ] && systemctl start "${SERVICE_NAME}" || true
    fail "服务端配置失败，已恢复旧程序。"
  fi

  rm -f -- "${backup}"
}

install_server() {
  local mode="${1:-prebuilt}"
  local temporary_dir source
  temporary_dir="$(mktemp -d)"
  trap 'rm -rf -- "${temporary_dir}"' EXIT
  SERVER_SOURCE=""

  if [ "${mode}" = "source" ]; then
    build_server_from_source
  else
    download_prebuilt_server "${temporary_dir}/${SERVER_ASSET}"
  fi
  source="${SERVER_SOURCE}"
  [ -n "${source}" ] || fail "未生成可安装的服务端程序。"
  install_server_binary "${source}"
  rm -rf -- "${temporary_dir}"
  trap - EXIT

  echo
  echo -e "${GREEN}Orange FRP 服务端 v${SERVER_VERSION} 安装完成。${RESET}"
  if [ "${mode}" = "prebuilt" ]; then
    echo -e "${GREEN}本次使用预编译静态程序，未安装 Rust 或编译工具链。${RESET}"
  fi
  echo -e "${GREEN}以后输入 ${CYAN}orange${GREEN} 即可唤出菜单栏。${RESET}"
}

verify_prebuilt_server() {
  local temporary_dir
  temporary_dir="$(mktemp -d)"
  trap 'rm -rf -- "${temporary_dir}"' EXIT
  SERVER_SOURCE=""
  download_prebuilt_server "${temporary_dir}/${SERVER_ASSET}"
  echo -e "${GREEN}预编译服务端校验通过：v${SERVER_VERSION}${RESET}"
  rm -rf -- "${temporary_dir}"
  trap - EXIT
}

main_menu() {
  while true; do
    title
    warn_root
    echo "1. 安装服务端（轻量预编译版）"
    echo "2. 退出安装"
    echo
    read -r -p "请选择操作: " choice
    case "${choice}" in
      1)
        install_server prebuilt
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
  require_platform
  case "${1:-}" in
    --install)
      install_server prebuilt
      ;;
    --build-from-source)
      install_server source
      ;;
    --verify-only)
      verify_prebuilt_server
      ;;
    --help|-h)
      echo "用法：sudo bash install.sh [--install|--build-from-source|--verify-only]"
      echo "默认和 --install 使用预编译静态程序；--build-from-source 才安装 Rust 和编译依赖。"
      ;;
    "")
      main_menu
      ;;
    *)
      fail "未知参数：$1"
      ;;
  esac
}

main "$@"
