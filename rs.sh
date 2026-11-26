#!/bin/sh
if [ -z "${BASH_VERSION:-}" ]; then
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache bash
    fi
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
fi

set -euo pipefail

# 可通过环境变量覆盖默认参数，例如：
# PORT=443 THREAD=100 TIMEOUT=5 WORK_DIR=/tmp/reality_scan bash run_reality_scan.sh
PORT="${PORT:-443}"
THREAD="${THREAD:-100}"
TIMEOUT="${TIMEOUT:-5}"
WORK_DIR="${WORK_DIR:-$(pwd)}"

SCAN_OUT="file.csv"
CHECKER_OUT="checker.csv"

log_info() {
    echo "[INFO] $*"
}

log_warn() {
    echo "[WARN] $*" >&2
}

log_err() {
    echo "[ERROR] $*" >&2
}

detect_os_and_arch() {
    OS_NAME="Unknown Linux"
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_NAME="${PRETTY_NAME:-${NAME:-Linux}}"
    fi

    ARCH_RAW="$(uname -m)"
    case "$ARCH_RAW" in
        x86_64 | amd64)
            ARCH_TAG="amd64"
            ;;
        aarch64 | arm64)
            ARCH_TAG="arm64"
            ;;
        *)
            log_err "不支持的系统架构: $ARCH_RAW（仅支持 x86_64/amd64 与 aarch64/arm64）"
            exit 1
            ;;
    esac

    log_info "检测到系统: $OS_NAME"
    log_info "检测到机器架构: $ARCH_RAW -> 映射为 $ARCH_TAG"
}

install_dependencies() {
    log_info "开始更新软件源并安装必要依赖..."
    if command -v apk >/dev/null 2>&1; then
        apk update
        apk add --no-cache unzip curl wget gcompat python3
    elif command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y unzip curl wget python3 ca-certificates
    else
        log_err "未找到支持的包管理器（apk 或 apt-get），请手动安装 unzip curl wget gcompat python3"
        exit 1
    fi
    log_info "依赖安装完成。"
}

download_tools() {
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"

    local scanner_url=""
    local checker_zip=""
    local checker_url=""

    if [ "$ARCH_TAG" = "amd64" ]; then
        scanner_url="https://github.com/XTLS/RealiTLScanner/releases/latest/download/RealiTLScanner-linux-amd64"
        checker_zip="reality-checker-linux-amd64.zip"
    elif [ "$ARCH_TAG" = "arm64" ]; then
        scanner_url="https://github.com/XTLS/RealiTLScanner/releases/latest/download/RealiTLScanner-linux-arm64"
        checker_zip="reality-checker-linux-arm64.zip"
    fi
    checker_url="https://github.com/V2RaySSR/RealityChecker/releases/latest/download/${checker_zip}"

    log_info "下载 RealiTLScanner ($ARCH_TAG)..."
    wget -q --show-progress -O RealiTLScanner "$scanner_url"
    chmod +x RealiTLScanner

    log_info "下载并解压 RealityChecker ($ARCH_TAG)..."
    rm -f "$checker_zip" reality-checker
    wget -q --show-progress -O "$checker_zip" "$checker_url"
    unzip -o -q "$checker_zip"
    rm -f "$checker_zip"

    if [ ! -f "./reality-checker" ]; then
        # 若压缩包内包含子目录或不同大小写文件名，尝试定位可执行文件
        local found_bin
        found_bin="$(find . -maxdepth 2 -type f -iname "*reality*checker*" ! -name "*.zip" | head -n 1 || true)"
        if [ -n "$found_bin" ]; then
            mv "$found_bin" ./reality-checker
        else
            log_err "解压后未找到 reality-checker 可执行文件"
            exit 1
        fi
    fi
    chmod +x ./reality-checker
    log_info "RealiTLScanner 与 RealityChecker 准备就绪。"
}

get_ipv4() {
    local ip=""
    local endpoints="https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip"
    for url in $endpoints; do
        ip="$(curl -4 -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            printf '%s' "$ip"
            return 0
        fi
    done
    return 1
}

ip_to_cidr24() {
    local ip="$1"
    local o1 o2 o3 o4
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    printf '%s.%s.%s.0/24' "$o1" "$o2" "$o3"
}

run_scan_and_check() {
    cd "$WORK_DIR"

    local vps_ip=""
    if ! vps_ip="$(get_ipv4)"; then
        log_err "无法自动获取服务器公网 IPv4 地址，请检查网络或手动指定。"
        exit 1
    fi

    local cidr_addr
    cidr_addr="$(ip_to_cidr24 "$vps_ip")"

    echo "------------------------------------------------------------------------"
    log_info "服务器公网 IPv4: $vps_ip"
    log_info "扫描同 /24 网段: $cidr_addr"
    log_info "执行命令: ./RealiTLScanner -addr $cidr_addr -port $PORT -thread $THREAD -timeout $TIMEOUT -out $SCAN_OUT"
    echo "------------------------------------------------------------------------"

    ./RealiTLScanner -addr "$cidr_addr" -port "$PORT" -thread "$THREAD" -timeout "$TIMEOUT" -out "$SCAN_OUT"

    if [ ! -f "$SCAN_OUT" ]; then
        log_warn "未生成 $SCAN_OUT（可能当前网段无符合条件的扫描结果），跳过后续解析与检测。"
        exit 0
    fi

    log_info "开始解析 $SCAN_OUT -> $CHECKER_OUT ..."
    python3 - <<'PY'
import csv
import os

inp = "file.csv"
out = "checker.csv"

bad_values = {
    "",
    "CloudFlare Origin Certificate",
}

seen = set()
valid_count = 0

with open(inp, newline="", encoding="utf-8-sig") as f, open(out, "w", newline="", encoding="utf-8") as g:
    r = csv.DictReader(f)
    w = csv.writer(g)

    # 兼容 RealityChecker 旧格式：第 3 列就是 CERT_DOMAIN
    w.writerow(["IP", "ORIGIN", "CERT_DOMAIN", "CERT_ISSUER", "GEO_CODE"])

    for row in r:
        ip = (row.get("IP") or "").strip()
        origin = (row.get("ORIGIN") or "").strip()
        domain = (row.get("CERT_DOMAIN") or "").strip()
        issuer = (row.get("CERT_ISSUER") or "").strip()
        geo = (row.get("GEO_CODE") or "").strip()

        if domain in bad_values:
            continue

        if domain.startswith("*."):
            domain = domain[2:]

        if "." not in domain:
            continue

        key = (ip, domain)
        if key in seen:
            continue
        seen.add(key)
        valid_count += 1

        w.writerow([ip, origin, domain, issuer, geo])

print(f"生成 {out}，有效记录 {valid_count} 条")
PY

    log_info "开始执行 ./reality-checker csv $CHECKER_OUT ..."
    ./reality-checker csv "$CHECKER_OUT"
}

main() {
    detect_os_and_arch
    install_dependencies
    download_tools
    run_scan_and_check
    log_info "全部流程执行完成！"
}

main "$@"
