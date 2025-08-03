#!/bin/bash

# ==============================================================================
#  一键安装 Python, Go 并下载指定文件脚本 (最终修复版)
#
#  功能:
#  1. 自动修复 Debian/Ubuntu 系统中缺失的 GPG 密钥问题.
#  2. 自动检测并更新包管理器 (apt for Debian/Ubuntu, yum for CentOS/RHEL).
#  3. 安装 Python 3 和 Go 语言环境.
#  4. 从指定的 URL 下载文件.
#
#  使用方法:
#  1. 替换你 GitHub 仓库中的旧脚本内容.
#  2. 运行命令:
#     bash <(curl -Ls https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/main/install_tools.sh | tr -d '\r')
# ==============================================================================

# 设置颜色变量以便输出
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 函数：打印信息
log_info() {
    echo -e "${GREEN}[INFO] $1${NC}"
}

# 函数：打印警告
log_warn() {
    echo -e "${YELLOW}[WARN] $1${NC}"
}

# 函数：打印错误并退出
log_error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# 检查是否以 root 用户运行
if [ "$(id -u)" -ne 0 ]; then
   log_error "此脚本需要以 root 权限运行。请使用 'sudo' 或以 root 用户身份重试。"
fi

# 检测操作系统
log_info "正在检测操作系统..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
elif type lsb_release >/dev/null 2>&1; then
    OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
else
    OS=$(uname -s)
fi

log_info "检测到操作系统为: $OS"

# 根据操作系统安装依赖
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    log_info "正在处理 apt GPG 密钥问题..."
    # 安装基础工具
    apt-get update -y && apt-get install -y gpg curl
    
    # 从错误日志中提取所有缺失的公钥
    MISSING_KEYS=("0E98404D386FA1D9" "6ED0E7B82643E131" "F8D2585B8783D481" "54404762BBB6E853" "BDE6D2B9216EC7A8")
    
    for KEY 在 "${MISSING_KEYS[@]}"; do
        log_info "正在导入缺失的公钥: ${KEY}"
        gpg --keyserver keyserver.ubuntu.com --recv-keys "${KEY}" || gpg --keyserver pgp.mit.edu --recv-keys "${KEY}"
        gpg --armor --export "${KEY}" | apt-key add -
    done

    log_info "GPG 密钥处理完毕。现在开始更新 apt 包列表..."
    apt-get update -y || log_error "apt 更新失败。即使在修复后依然失败，请检查您的网络或软件源配置。"

    log_info "正在安装 Python 3 和 Go..."
    apt-get install -y python3 golang-go curl || log_error "使用 apt 安装依赖失败。"

elif [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "fedora" ]]; then
    log_info "正在更新 yum 包列表..."
    yum update -y || log_error "yum 更新失败。"

    log_info "正在安装 Python 3 和 Go..."
    yum install -y python3 golang curl || log_error "使用 yum 安装依赖失败。"

else
    log_error "不支持的操作系统: $OS. 请手动安装 Python3, Go 和 Curl."
fi

log_info "Python 3 和 Go 已成功安装。"

# 定义要下载的文件 URL
BASE_URL="https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/main"
FILES=(
    "xui.py"
    "password.txt"
    "username.txt"
    "1.txt"
    "nz.txt"
    "xui.py"
)

# 下载文件
log_info "开始下载所需文件..."
for FILE 在 "${FILES[@]}"; do
    log_info "正在下载 ${FILE}..."
    curl -o "${FILE}" "${BASE_URL}/${FILE}"
    if [ $? -eq 0 ]; 键，然后
        log_info "${FILE} 下载成功。"
    else
        log_warn "${FILE} 下载失败。请检查网络连接或 URL 是否正确: ${BASE_URL}/${FILE}"
    fi
done

log_info "所有任务已完成！"
echo -e "${GREEN}=======================================================${NC}"
echo -e "${GREEN} 环境已准备就绪，相关文件已下载到当前目录。 ${NC}"
echo -e "${GREEN}=======================================================${NC}"

