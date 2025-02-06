import argparse
import subprocess
import platform
import socket
import sys
from concurrent.futures import ThreadPoolExecutor


def is_host_alive(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def is_port_open(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex((ip, port)) == 0


def reverse_dns_check(ip, allowed_domain):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return allowed_domain in hostname
    except socket.herror:
        return False


def scan_ports(ip, ports):
    open_ports = []
    for port in sorted(ports):
        if is_port_open(ip, port):
            print(f"    [*] Port {port} is open")
            open_ports.append(port)
        else:
            print(f"    [-] Port {port} is closed")
    return open_ports


def scan_host(ip, ports, allowed_domain=None, output_file=None, alive_hosts=set()):
    if is_host_alive(ip):
        if allowed_domain and not reverse_dns_check(ip, allowed_domain):
            print(f"[-] Host {ip} does not belong to allowed domain")
            return
        print(f"[+] Host {ip} is alive")
        open_ports = scan_ports(ip, ports)
        if output_file and open_ports and ip not in alive_hosts:
            alive_hosts.add(ip)
            with open(output_file, 'a') as f:
                f.write(f"{ip}/{','.join(map(str, open_ports))}\n")
    else:
        print(f"[-] Host {ip} is not reachable")


def parse_range(range_str):
    start, end = map(int, range_str.split('-'))
    return range(start, end + 1)


def load_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines() if line.strip()]


def parse_ips(args):
    ips = set()
    if args.subnet:
        base_ip = '.'.join(args.subnet.split('.')[:3])
        ips.update(f"{base_ip}.{i}" for i in range(1, 255))
    if args.ip_range:
        base_ip = '.'.join(args.ip_range.split('.')[:3])
        ip_range = parse_range(args.ip_range.split('.')[-1])
        ips.update(f"{base_ip}.{i}" for i in ip_range)
    if args.ip_list:
        ips.update(args.ip_list.replace(' ', '').split(','))
    if args.ip_file:
        ips.update(load_from_file(args.ip_file))
    return sorted(ips)


def parse_ports(args):
    ports = set()
    if args.port:
        ports.add(args.port)
    if args.port_range:
        ports.update(parse_range(args.port_range))
    if args.port_list:
        cleaned_ports = args.port_list.replace(' ', '')
        ports.update(map(int, cleaned_ports.split(',')))
    if args.port_file:
        ports.update(map(int, load_from_file(args.port_file)))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(description="Flexible Subnet, IP, and Port Scanner")
    parser.add_argument('-s', '--subnet', help="Subnet to scan (e.g., 192.168.1.0)")
    parser.add_argument('-ip', '--ip-range', help="Range of IPs to scan (e.g., 192.168.1.10-20)")
    parser.add_argument('-il', '--ip-list', help="Comma-separated list of IPs to scan (e.g., 192.168.1.1,192.168.1.2)")
    parser.add_argument('-if', '--ip-file', help="File containing list of IPs to scan")
    parser.add_argument('-p', '--port', type=int, help="Single port to scan")
    parser.add_argument('-rp', '--port-range', help="Range of ports to scan (e.g., 20-25)")
    parser.add_argument('-pl', '--port-list', help="Comma-separated list of ports to scan (e.g., 22,80,443)")
    parser.add_argument('-pf', '--port-file', help="File containing list of ports to scan")
    parser.add_argument('-t', '--threads', type=int, default=4, help="Number of parallel threads")
    parser.add_argument('-ad', '--allowed-domain', help="Restrict scan to IPs resolving to this domain")
    parser.add_argument('-o', '--output', help="Output file for alive IPs with open ports")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    try:
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        sys.exit(1)

    ips = parse_ips(args)
    ports = parse_ports(args)
    alive_hosts = set()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(lambda ip: scan_host(ip, ports, args.allowed_domain, args.output, alive_hosts), ips)

    if args.output:
        with open(args.output, 'r') as f:
            unique_ips = sorted(set(f.readlines()))
        with open(args.output, 'w') as f:
            f.writelines(unique_ips)


if __name__ == "__main__":
    main()

