#!/usr/bin/env python3
"""
portknock - async port knocking tool
by r00t26

Usage:
  portknock <host> <port1> <port2> <port3> ...
  portknock <host> <port1> <port2> --udp
  portknock <host> <port1> <port2> --scan 22,80,443
  portknock <host> <port1> <port2> --grab
  portknock <host> <port1> <port2> --delay 500
"""

import asyncio
import socket
import argparse
import sys
import struct
import time
from typing import Optional

# ---Colours---

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
DIM    = "\033[2m"
WHITE  = "\033[97m"

def c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"

def banner():
    print(f"""
{CYAN}{BOLD}  ██████╗  ██████╗ ██████╗ ████████╗██╗  ██╗███╗   ██╗ ██████╗  ██████╗██╗  ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██║ ██╔╝████╗  ██║██╔═══██╗██╔════╝██║ ██╔╝
  ██████╔╝██║   ██║██████╔╝   ██║   █████╔╝ ██╔██╗ ██║██║   ██║██║     █████╔╝ 
  ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔═██╗ ██║╚██╗██║██║   ██║██║     ██╔═██╗ 
  ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██╗██║ ╚████║╚██████╔╝╚██████╗██║  ██╗
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝{RESET}
  {DIM}async port knocking tool · by r00t26{RESET}
""")

def info(msg):  print(f"  {c(CYAN,  '[*]')} {msg}")
def ok(msg):    print(f"  {c(GREEN, '[+]')} {msg}")
def fail(msg):  print(f"  {c(RED,   '[-]')} {msg}")
def warn(msg):  print(f"  {c(YELLOW,'[!]')} {msg}")
def dim(msg):   print(f"  {c(DIM,   '   ')} {msg}")



# ---TCP Knock---

async def tcp_knock(host: str, port: int, timeout: float = 1.0) -> bool:
    """Send a single TCP knock. Returns True if connection was accepted."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False



# ---UDP Knock---

async def udp_knock(host: str, port: int) -> None:
    """Send a single UDP knock packet."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _udp_send, host, port)

def _udp_send(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    try:
        sock.sendto(b'\x00', (host, port))
    finally:
        sock.close()



# ---Knock Sequence---

async def run_knock_sequence(
    host: str,
    ports: list[int],
    use_udp: bool = False,
    delay_ms: int = 100,
) -> None:
    protocol = "UDP" if use_udp else "TCP"
    info(f"Knocking {c(WHITE, host)} via {c(CYAN, protocol)}")
    info(f"Sequence: {c(CYAN, ' → '.join(str(p) for p in ports))}")
    print()

    for i, port in enumerate(ports, 1):
        if use_udp:
            await udp_knock(host, port)
            ok(f"Knock {i}/{len(ports)} → port {c(WHITE, str(port))} {c(DIM, '(UDP — no response expected)')}")
        else:
            accepted = await tcp_knock(host, port)
            status = c(GREEN, "accepted") if accepted else c(DIM, "closed/filtered")
            ok(f"Knock {i}/{len(ports)} → port {c(WHITE, str(port))}  {status}")

        if i < len(ports):
            await asyncio.sleep(delay_ms / 1000)

    print()
    ok(f"Knock sequence complete.")



# ---Port Scan---

async def scan_port(host: str, port: int, timeout: float = 2.0) -> tuple[int, bool]:
    """Async TCP connect scan of a single port."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port, True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False

async def run_scan(host: str, ports: list[int]) -> list[int]:
    print()
    info(f"Scanning {len(ports)} port(s) on {c(WHITE, host)} ...")
    tasks = [scan_port(host, p) for p in ports]
    results = await asyncio.gather(*tasks)

    open_ports = []
    for port, is_open in sorted(results):
        if is_open:
            ok(f"Port {c(GREEN, str(port))}/tcp  {c(GREEN, 'OPEN')}")
            open_ports.append(port)
        else:
            dim(f"Port {port}/tcp  {c(DIM, 'closed')}")

    if not open_ports:
        warn("No open ports found.")
    else:
        print()
        ok(f"{len(open_ports)} open port(s) found.")

    return open_ports



# ---Banner Grab---

async def grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Attempt to grab a service banner from an open port."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)

        # Send a generic probe for HTTP, otherwise just read
        if port in (80, 8080, 8000, 8443, 443):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            await writer.drain()
        else:
            writer.write(b"\r\n")
            await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = data.decode(errors="replace").strip()
        except asyncio.TimeoutError:
            banner = None

        writer.close()
        await writer.wait_closed()
        return banner if banner else None

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

# Known service names for common ports
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

async def run_banner_grab(host: str, ports: list[int]) -> None:
    print()
    info(f"Grabbing banners from {len(ports)} open port(s)...")
    print()

    tasks = [grab_banner(host, p) for p in ports]
    banners = await asyncio.gather(*tasks)

    for port, banner in zip(ports, banners):
        service = COMMON_SERVICES.get(port, "unknown")
        print(f"  {c(CYAN, f'PORT {port}')}/{c(DIM, service)}")
        if banner:
            # Print first line of banner, truncated
            first_line = banner.splitlines()[0][:120]
            print(f"    {c(GREEN, '↳')} {c(WHITE, first_line)}")
            if len(banner.splitlines()) > 1:
                for line in banner.splitlines()[1:3]:
                    print(f"      {c(DIM, line[:120])}")
        else:
            print(f"    {c(DIM, '↳ no banner received')}")
        print()



# ---Argument Parsing---

def parse_ports(port_str: str) -> list[int]:
    """Parse a comma-separated port string like '22,80,443' into a list."""
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portknock",
        description="Async port knocking tool with scan and banner grabbing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  portknock 10.10.10.1 7000 8000 9000
  portknock 10.10.10.1 7000 8000 9000 --udp
  portknock 10.10.10.1 7000 8000 9000 --scan 22,80,443
  portknock 10.10.10.1 7000 8000 9000 --scan 1-1024
  portknock 10.10.10.1 7000 8000 9000 --scan 22,80 --grab
  portknock 10.10.10.1 7000 8000 9000 --delay 500
        """
    )
    parser.add_argument("host", help="Target host (IP or hostname)")
    parser.add_argument("ports", nargs="+", type=int, help="Knock sequence ports")
    parser.add_argument("--udp", action="store_true", help="Use UDP for knock packets")
    parser.add_argument(
        "--scan", metavar="PORTS",
        help="Scan these ports after knocking (e.g. 22,80,443 or 1-1024)"
    )
    parser.add_argument(
        "--grab", action="store_true",
        help="Grab banners from open ports found during scan"
    )
    parser.add_argument(
        "--delay", type=int, default=100, metavar="MS",
        help="Delay between knocks in milliseconds (default: 100)"
    )
    parser.add_argument(
        "--scan-timeout", type=float, default=2.0, metavar="SEC",
        help="Timeout per port during scan (default: 2.0)"
    )
    return parser



# ---Main---

async def main():
    parser = build_parser()
    args = parser.parse_args()

    banner()

    start = time.time()

    # 1. Knock sequence
    await run_knock_sequence(
        host=args.host,
        ports=args.ports,
        use_udp=args.udp,
        delay_ms=args.delay,
    )

    # 2. Optional post-knock scan
    open_ports = []
    if args.scan:
        scan_ports = parse_ports(args.scan)
        open_ports = await run_scan(args.host, scan_ports)

    # 3. Optional banner grab (only on open ports from scan)
    if args.grab:
        if not open_ports:
            warn("--grab specified but no open ports to grab from. Run with --scan first.")
        else:
            await run_banner_grab(args.host, open_ports)

    elapsed = time.time() - start
    print(f"  {c(DIM, f'Done in {elapsed:.2f}s')}\n")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n  {c(YELLOW, '[!]')} Interrupted.\n")
        sys.exit(0)
