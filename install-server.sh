#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="juzihensuan/Orange-FRP"
BRANCH="main"
PACKAGE_INSTALLER_URL="${ORANGE_FRP_PACKAGE_INSTALLER_URL:-https://raw.githubusercontent.com/${REPOSITORY}/${BRANCH}/server-package/install.sh}"
PACKAGE_INSTALLER_SHA256="${ORANGE_FRP_PACKAGE_INSTALLER_SHA256:-d42dbadd1335253b14ae898a410ef143013419c476171540eae6881c95c46361}"
MAX_INSTALLER_BYTES=$((128 * 1024))

RED="\033[31;1m"
GREEN="\033[32;1m"
CYAN="\033[36;1m"
RESET="\033[0m"

fail() {
  echo -e "${RED}安装失败：$*${RESET}" >&2
  exit 1
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

[ "$(uname -s)" = "Linux" ] || fail "Orange FRP 服务端仅支持 Linux。"
[ "$(id -u)" -eq 0 ] || fail "请使用 root 权限运行，例如：curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/${BRANCH}/install-server.sh | sudo bash"

for command in curl bash mktemp wc; do
  command -v "${command}" >/dev/null 2>&1 || fail "缺少必要命令：${command}"
done

temporary_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "${temporary_dir}"
}
trap cleanup EXIT

installer="${temporary_dir}/install.sh"
echo -e "${CYAN}正在下载 Orange FRP 轻量安装器...${RESET}"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "${PACKAGE_INSTALLER_URL}" -o "${installer}"

installer_size="$(wc -c < "${installer}")"
[ "${installer_size}" -gt 0 ] || fail "下载的安装器为空。"
[ "${installer_size}" -le "${MAX_INSTALLER_BYTES}" ] || fail "下载的安装器超过大小限制。"
[ "$(sha256_file "${installer}")" = "${PACKAGE_INSTALLER_SHA256}" ] \
  || fail "安装器 SHA-256 校验失败，已拒绝执行。"
head -n 1 "${installer}" | grep -q '^#!/usr/bin/env bash$' \
  || fail "下载的安装器格式不正确。"

echo -e "${CYAN}校验通过，开始安装预编译服务端...${RESET}"
bash "${installer}" --install

echo -e "${GREEN}Orange FRP 服务端一键安装完成。输入 orange 即可打开管理菜单。${RESET}"
