# ridwalk

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](https://github.com/yourusername/ridwalk)

SMB user and group enumeration via RID cycling. Supports Windows Active Directory and Unix/Linux Samba environments.

## Features

- RID cycling enumeration for user and group discovery
- Automatic target detection (Windows AD / Unix Samba)
- Multi-threaded scanning with configurable thread count
- Anonymous and authenticated enumeration modes
- Comprehensive input validation and error handling

## Installation

Requires `rpcclient` from the Samba suite:

```bash
# Ubuntu/Debian
sudo apt install smbclient

# macOS
brew install samba

# Windows (WSL)
sudo apt install smbclient
```

Then clone and setup ridwalk:

```bash
git clone https://github.com/yourusername/ridwalk.git
cd ridwalk
chmod +x ridwalk.py
```

## Usage

```bash
# Anonymous enumeration
./ridwalk.py 10.10.10.10

# Prompt for password
./ridwalk.py 10.10.10.10 -U administrator

# Custom RID range
./ridwalk.py 10.10.10.10 -r 500-2000

# Users only with specific range
./ridwalk.py 10.10.10.10 -u -r 1000-2000

# Authenticated scan with output file
./ridwalk.py 10.10.10.10 -U admin -o results.txt

# Multi-range enumeration with verbose output
./ridwalk.py 10.10.10.10 -r 500-600,1000-1100 -v

# High-performance scanning
./ridwalk.py 10.10.10.10 -t 30 -r 500-1500
```

## Command Line Options

```
./ridwalk.py <target> [options]

Arguments:
  target                SMB server IP address

Options:
  -r, --range           RID range (default: 1000-1050)
  -t, --threads         Thread count (default: 10, max: 50)
  -U, --username        Authentication username
  -P, --password        Authentication password
  -u, --users           Enumerate users only
  -g, --groups          Enumerate groups only
  -o, --output          Save results to file
  -v, --verbose         Detailed progress output
  -q, --quiet           Minimal output mode
  --version             Display version information
```

## Sample Output

```
[*] Target: 10.10.10.10 (Windows AD)
[*] Authentication: anonymous
[*] Domain SID: S-1-5-21-1234567890-987654321-1122334455

RID    Type   Name
--------------------------------------------------
500    User   Administrator
512    Group  Domain Admins
1001   User   alice
1002   User   bob
```

## Troubleshooting

**"rpcclient not found"**
Install samba tools: `sudo apt install smbclient`

**"Connection refused"**
Verify SMB service is running and accessible

**"Authentication failed"**
Check credentials or try anonymous mode

## Technical Notes

- Effectiveness depends on target SMB configuration and security controls
- Modern systems may implement RID cycling protections
- High thread counts may trigger rate limiting or detection mechanisms
- Tool performance varies based on network latency and target responsiveness

## RID Cycling Overview

RID (Relative Identifier) cycling leverages the sequential nature of Windows security identifiers to enumerate domain objects. This technique queries ranges of RIDs to discover user and group accounts that may not be accessible through other enumeration methods.

---

**Intended for authorized security testing only. Obtain proper authorization before use.**
