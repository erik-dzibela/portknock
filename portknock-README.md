# portknock

Async port knocking tool with post-knock scanning and banner grabbing. Built for HTB and CTF workflows.

## Features

- TCP and UDP knock sequences
- Async port scan after knocking (verify a port opened)
- Banner grabbing / service fingerprinting on open ports
- Configurable delay between knocks
- Coloured terminal output

## Requirements

Python 3.10+ (uses `asyncio`). No external dependencies — stdlib only.

## Usage

```bash
# Basic TCP knock sequence
python3 portknock.py 10.10.10.1 7000 8000 9000

# UDP knock sequence
python3 portknock.py 10.10.10.1 7000 8000 9000 --udp

# Knock then scan specific ports
python3 portknock.py 10.10.10.1 7000 8000 9000 --scan 22,80,443

# Knock, scan a range, grab banners
python3 portknock.py 10.10.10.1 7000 8000 9000 --scan 1-1024 --grab

# Custom delay between knocks (ms)
python3 portknock.py 10.10.10.1 7000 8000 9000 --delay 500
```

## Options

| Flag | Description |
|------|-------------|
| `--udp` | Use UDP for knock packets instead of TCP |
| `--scan PORTS` | Scan ports after knocking (e.g. `22,80,443` or `1-1024`) |
| `--grab` | Grab service banners from open ports found during scan |
| `--delay MS` | Delay between knocks in milliseconds (default: 100) |
| `--scan-timeout SEC` | Per-port timeout during scan (default: 2.0) |
