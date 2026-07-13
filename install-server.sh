#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="juzihensuan/Orange-FRP"
BRANCH="main"
ARCHIVE_URL="https://github.com/${REPOSITORY}/archive/refs/heads/${BRANCH}.tar.gz"

RED="\033[31;1m"
GREEN="\033[32;1m"
CYAN="\033[36;1m"
RESET="\033[0m"

fail() {
  echo -e "${RED}安装失败：$*${RESET}" >&2
  exit 1
}

install_archive_tools() {
  if command -v tar >/dev/null 2>&1 && command -v gzip >/dev/null 2>&1; then
    return
  fi

  echo -e "${CYAN}正在安装源码解压工具...${RESET}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y tar gzip
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y tar gzip
  elif command -v yum >/dev/null 2>&1; then
    yum install -y tar gzip
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm tar gzip
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install tar gzip
  else
    fail "缺少 tar/gzip，且未识别可用的包管理器。"
  fi
}

if [ "$(uname -s)" != "Linux" ]; then
  fail "Orange FRP 服务端仅支持 Linux。"
fi

if [ "$(id -u)" -ne 0 ]; then
  fail "请使用 root 权限运行，例如：curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/${BRANCH}/install-server.sh | sudo bash"
fi

install_archive_tools

for command in curl tar gzip find mktemp; do
  command -v "${command}" >/dev/null 2>&1 || fail "缺少必要命令：${command}"
done

temporary_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "${temporary_dir}"
}
trap cleanup EXIT

archive="${temporary_dir}/orange-frp.tar.gz"
echo -e "${CYAN}正在从 GitHub 下载 Orange FRP 服务端源码...${RESET}"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "${ARCHIVE_URL}" -o "${archive}"
tar -xzf "${archive}" -C "${temporary_dir}"

installer="$(find "${temporary_dir}" -type f -path '*/server-package/install.sh' -print -quit)"
[ -n "${installer}" ] || fail "下载内容中未找到 server-package/install.sh。"

bundle_dir="$(dirname -- "${installer}")"
echo -e "${CYAN}源码下载完成，开始编译并安装...${RESET}"
ORANGE_FRP_ROOT="${bundle_dir}" bash "${installer}" --install

echo -e "${GREEN}Orange FRP 服务端一键安装完成。输入 orange 即可打开管理菜单。${RESET}"
