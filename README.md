# Subnet & Port Scanner

A **flexible and multithreaded network scanner** that allows users to scan subnets, specific IPs, and port ranges efficiently. This tool also provides domain-based filtering and an option to save results.

## Features
- Scan a **subnet, a range of IPs, or specific IPs**.
- Scan **a single port, a range of ports, or a list of ports**.
- **Multithreaded scanning** for improved speed.
- Check if hosts are alive before scanning ports.
- **Restrict scanning to a specific domain** (reverse DNS check).
- Save results to a file (`-o` option) containing only live IPs with open ports.
- **Supports input from text files** for both IPs and ports.

## Usage

### Basic Syntax
```bash
python scanner.py [options]
```

### Arguments

| Option | Description |
|--------|-------------|
| `-s, --subnet` | Subnet to scan (e.g., `192.168.1.0`) |
| `-ip, --ip-range` | Range of IPs to scan (e.g., `192.168.1.10-20`) |
| `-il, --ip-list` | Comma-separated list of IPs (e.g., `192.168.1.1,192.168.1.2`) |
| `-if, --ip-file` | File containing a list of IPs to scan |
| `-p, --port` | Single port to scan (e.g., `80`) |
| `-rp, --port-range` | Range of ports (e.g., `20-25`) |
| `-pl, --port-list` | Comma-separated list of ports (e.g., `22,80,443`) |
| `-pf, --port-file` | File containing a list of ports |
| `-t, --threads` | Number of parallel threads (default: `4`) |
| `-ad, --allowed-domain` | Restrict scan to IPs resolving to a specific domain |
| `-o, --output` | Output file to save live IPs with detected open ports |

### Examples

#### Scan a subnet for a specific port
```bash
python scanner.py -s 192.168.1.0 -p 80 -t 4
```

#### Scan a range of IPs for multiple ports
```bash
python scanner.py -ip 192.168.1.10-50 -pl 22,53,80 -t 10
```

#### Scan specific IPs from a file
```bash
python scanner.py -if ips.txt -rp 20-100
```

#### Restrict scan to a domain (reverse DNS check)
```bash
python scanner.py -s 172.1.2.0 -p 80 -t 4 -ad example.com
```

#### Save alive hosts with open ports to a file
```bash
python scanner.py -s 192.168.1.0 -p 80 -o alive_hosts.txt
```

## Installation & Dependencies

Ensure **Python 3.6+** is installed. No additional libraries are required, as the tool uses built-in modules.

Clone the repository:
```bash
git clone https://github.com/mrxehmad/port-scanner2.0.git
cd port-scanner2.0
```

Run the script:
```bash
python scanner.py --help
```

## License
MIT License - Free to use and modify.

## Contribution
Feel free to fork the repository and submit pull requests to improve the tool.

