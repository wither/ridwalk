#!/usr/bin/env python3
import subprocess
import re
import argparse
import sys
import time
import ipaddress
import getpass
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "1.0.0"
__author__ = "wither"

class C:
    G = '\033[92m'
    Y = '\033[93m'
    R = '\033[91m'
    B = '\033[94m'
    E = '\033[0m'

class ValidationError(Exception):
    pass

class AuthenticationError(Exception):
    pass

class NetworkError(Exception):
    pass

def validate_rid_range(range_str):
    try:
        for r in range_str.split(','):
            start, end = map(int, r.strip().split('-'))
            if start < 0 or end < 0:
                raise ValidationError("RID values must be non-negative")
            if start > 100000 or end > 100000:
                raise ValidationError("RID values should not exceed 100000")
            if start > end:
                raise ValidationError("Start of range must be <= end")
            if end - start > 10000:
                raise ValidationError("Single range cannot exceed 10000 RIDs")
        return True
    except ValueError:
        raise ValidationError("Range format must be 'start-end' or 'start1-end1,start2-end2'")

def validate_domain_sid(sid):
    if not re.match(r'^[0-9]+-[0-9]+-[0-9]+$', sid):
        raise ValidationError("Domain SID format must be 'number-number-number'")
    return True

def validate_username(username):
    if len(username) > 64:
        raise ValidationError("Username cannot exceed 64 characters")
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        raise ValidationError("Username contains invalid characters")
    return True

def validate_output_path(path):
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.exists(directory):
        raise ValidationError(f"Output directory does not exist: {directory}")
    if not os.access(directory, os.W_OK):
        raise ValidationError(f"No write permission for directory: {directory}")
    return True

def run_rpcclient(ip, command, username="", password="", timeout=10):
    try:
        cmd = ["rpcclient"]
        if username:
            cmd.extend(["-U", f"{username}%{password}" if password else username])
        else:
            cmd.extend(["-U", "", "-N"])
        cmd.extend([ip, "-c", command])
        
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        
        if result.returncode == 1 and "NT_STATUS_LOGON_FAILURE" in result.stderr:
            raise AuthenticationError("Authentication failed - invalid credentials")
        elif result.returncode == 1 and "NT_STATUS_ACCESS_DENIED" in result.stderr:
            raise AuthenticationError("Access denied - insufficient privileges")
        elif result.returncode == 1 and ("Connection refused" in result.stderr or "No route to host" in result.stderr):
            raise NetworkError(f"Cannot connect to {ip}")
        
        return result
        
    except subprocess.TimeoutExpired:
        raise NetworkError(f"Connection timeout to {ip}")
    except FileNotFoundError:
        print(f"{C.R}[!]{C.E} Error: rpcclient not found. Install samba-common-bin package.")
        sys.exit(1)
    except OSError as e:
        raise NetworkError(f"System error: {e}")

def get_domain_sid(ip, username="", password="", timeout=15):
    try:
        result = run_rpcclient(ip, "lsaquery", username, password, timeout)
        if not result or result.returncode != 0:
            return None
        
        patterns = [r"Domain Sid:\s*S-1-5-21-([0-9-]+)", r"Domain SID:\s*S-1-5-21-([0-9-]+)", r"SID:\s*S-1-5-21-([0-9-]+)"]
        for pattern in patterns:
            match = re.search(pattern, result.stdout, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    except (AuthenticationError, NetworkError):
        return None

def detect_target_type(ip, username="", password="", verbose=False):
    if verbose:
        print(f"{C.Y}[*]{C.E} Detecting target type...", end="", flush=True)
    
    try:
        domain_sid = get_domain_sid(ip, username, password)
        if domain_sid:
            if verbose:
                print(f"\r{C.G}[+]{C.E} Windows AD detected (Domain SID: S-1-5-21-{domain_sid})")
            return "windows", domain_sid
        
        if verbose:
            print(f"\r{C.Y}[*]{C.E} Testing for Unix/Linux Samba...", end="", flush=True)
        result = run_rpcclient(ip, "lookupsids S-1-22-1-1000", username, password)
        if result and result.returncode == 0 and "Unix User" in result.stdout:
            if verbose:
                print(f"\r{C.G}[+]{C.E} Unix/Linux Samba detected")
            return "unix", None
        
        if verbose:
            print(f"\r{C.G}[+]{C.E} Defaulting to Unix/Linux Samba")
        return "unix", None
        
    except AuthenticationError as e:
        if verbose:
            print(f"\r{C.R}[!]{C.E} Authentication error during detection: {e}")
        raise
    except NetworkError as e:
        if verbose:
            print(f"\r{C.R}[!]{C.E} Network error during detection: {e}")
        raise

def batch_lookup_unix_rids(ip, rids, username="", password="", timeout=10):
    results = []
    
    try:
        user_sids = [f"S-1-22-1-{rid}" for rid in rids]
        group_sids = [f"S-1-22-2-{rid}" for rid in rids]
        all_sids = user_sids + group_sids
        
        sid_batch = " ".join(all_sids)
        result = run_rpcclient(ip, f"lookupsids {sid_batch}", username, password, timeout)
        
        if result and result.returncode == 0:
            for rid in rids:
                rid_results = []
                
                user_pattern = f"S-1-22-1-{rid}.*Unix User\\\\([^\\s\\\\]+)"
                user_match = re.search(user_pattern, result.stdout)
                if user_match:
                    username_found = user_match.group(1)
                    if not username_found.isdigit() and username_found:
                        rid_results.append(("User", username_found))
                
                group_pattern = f"S-1-22-2-{rid}.*Unix Group\\\\([^\\s\\\\]+)"
                group_match = re.search(group_pattern, result.stdout)
                if group_match:
                    groupname = group_match.group(1)
                    if not groupname.isdigit() and groupname:
                        user_names = [name for obj_type, name in rid_results if obj_type == "User"]
                        if not user_names or groupname not in user_names:
                            rid_results.append(("Group", groupname))
                
                if rid_results:
                    for obj_type, name in rid_results:
                        results.append((rid, obj_type, name))
        
        return results
        
    except (AuthenticationError, NetworkError):
        raise

def lookup_windows_rid(ip, rid, domain_sid, username="", password="", timeout=10):
    if not domain_sid:
        return None
    
    try:
        sid = f"S-1-5-21-{domain_sid}-{rid}"
        result = run_rpcclient(ip, f"lookupsids {sid}", username, password, timeout)
        if not result or result.returncode != 0:
            return None
        
        user_patterns = [r"([A-Z0-9-]+)\\([^\s\\]+)\s+\(1\)", r"\\([^\s\\]+)\s+\(1\)"]
        group_patterns = [r"([A-Z0-9-]+)\\([^\s\\]+)\s+\(2\)", r"\\([^\s\\]+)\s+\(2\)"]
        fallback_patterns = [r"([A-Z0-9-]+)\\([^\s\\]+)", r"\\([^\s\\]+)"]
        
        for pattern in user_patterns:
            match = re.search(pattern, result.stdout)
            if match:
                if len(match.groups()) == 2:
                    domain, name = match.groups()
                    if not name.isdigit() and name.lower() not in ['nobody', 'nogroup']:
                        return "User", f"{domain}\\{name}"
                else:
                    name = match.group(1)
                    if not name.isdigit() and name.lower() not in ['nobody', 'nogroup']:
                        return "User", name
        
        for pattern in group_patterns:
            match = re.search(pattern, result.stdout)
            if match:
                if len(match.groups()) == 2:
                    domain, name = match.groups()
                    if not name.isdigit() and name.lower() not in ['nobody', 'nogroup']:
                        return "Group", f"{domain}\\{name}"
                else:
                    name = match.group(1)
                    if not name.isdigit() and name.lower() not in ['nobody', 'nogroup']:
                        return "Group", name
        
        if "Domain Admins" in result.stdout or "Domain Users" in result.stdout or " Group" in result.stdout:
            for pattern in fallback_patterns:
                match = re.search(pattern, result.stdout)
                if match:
                    if len(match.groups()) == 2:
                        domain, name = match.groups()
                        if not name.isdigit() and name.lower() not in ['nobody', 'nogroup']:
                            return "Group", f"{domain}\\{name}"
                    else:
                        name = match.group(1)
                        if not name.isdigit() and name.lower() not in ['nobody', 'nogroup']:
                            return "Group", name
        
        return None
        
    except (AuthenticationError, NetworkError):
        raise

def scan_rid_batch(ip, rid_batch, target_type, domain_sid, scan_users=True, scan_groups=True, username="", password="", timeout=10):
    results = []
    
    try:
        if target_type == "unix":
            unix_results = batch_lookup_unix_rids(ip, rid_batch, username, password, timeout)
            for rid, obj_type, name in unix_results:
                if (obj_type == "User" and scan_users) or (obj_type == "Group" and scan_groups):
                    results.append((rid, obj_type, name))
        else:
            for rid in rid_batch:
                result = lookup_windows_rid(ip, rid, domain_sid, username, password, timeout)
                if result:
                    obj_type, name = result
                    if (obj_type == "User" and scan_users) or (obj_type == "Group" and scan_groups):
                        results.append((rid, obj_type, name))
        
        return results
        
    except (AuthenticationError, NetworkError):
        raise

def parse_range(range_str):
    def parse_single(r):
        start, end = map(int, r.split('-'))
        return start, end
    
    rid_set = set()
    for r in range_str.split(','):
        start, end = parse_single(r.strip())
        rid_set.update(range(start, end + 1))
    
    return sorted(rid_set)

def show_connection_status(ip, username, target_type, domain_sid=None):
    auth_status = f"{C.B}authenticated as {username}{C.E}" if username else f"{C.Y}anonymous{C.E}"
    target_desc = f"{C.G}Windows AD{C.E}" if target_type == "windows" else f"{C.G}Unix/Linux Samba{C.E}"
    
    print(f"{C.Y}[*]{C.E} Target: {ip} ({target_desc})")
    print(f"{C.Y}[*]{C.E} Authentication: {auth_status}")
    if domain_sid:
        print(f"{C.Y}[*]{C.E} Domain SID: S-1-5-21-{domain_sid}")
    
    try:
        test_result = run_rpcclient(ip, "getdompwinfo", username, "", 5)
        if test_result and test_result.returncode == 0:
            print(f"{C.G}[+]{C.E} Connection status: {C.G}OK{C.E}")
        else:
            print(f"{C.Y}[+]{C.E} Connection status: {C.Y}Limited{C.E}")
    except (AuthenticationError, NetworkError) as e:
        print(f"{C.R}[!]{C.E} Connection status: {C.R}Error - {e}{C.E}")

def show_performance_summary(total_rids, found_count, error_count, elapsed):
    print(f"\n{C.Y}Performance Summary:{C.E}")
    print(f"{C.Y}[*]{C.E} RIDs scanned: {total_rids}")
    print(f"{C.Y}[*]{C.E} Objects found: {C.G}{found_count}{C.E}")
    print(f"{C.Y}[*]{C.E} Errors encountered: {C.R}{error_count}{C.E}")
    print(f"{C.Y}[*]{C.E} Success rate: {C.G}{((total_rids - error_count) / total_rids * 100):.1f}%{C.E}")
    print(f"{C.Y}[*]{C.E} Total time: {elapsed:.1f}s")
    if elapsed > 0:
        print(f"{C.Y}[*]{C.E} Average rate: {total_rids/elapsed:.1f} RIDs/s")
        print(f"{C.Y}[*]{C.E} Discovery rate: {found_count/elapsed:.1f} objects/s")

def main():
    parser = argparse.ArgumentParser(
        description="ridwalk: Enumerate SMB users and groups via RID cycling",
        epilog="Examples:\n"
               "  ridwalk.py 10.10.137.1\n"
               "  ridwalk.py 10.10.137.1 -r 500-1000\n"
               "  ridwalk.py 10.10.137.1 -u\n"
               "  ridwalk.py 10.10.137.1 -g -r 0-100\n"
               "  ridwalk.py 10.10.137.1 -U admin -P password\n"
               "  ridwalk.py 10.10.137.1 -v -r 500-550,1000-1050\n"
               "  ridwalk.py 10.10.137.1 -U admin -g -r 500-600 -t 20 -o results.txt\n"
               "  ridwalk.py 10.10.137.1 --os windows -s 123-456-789 -b 50",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--version", action="version", version=f"ridwalk {__version__}")
    parser.add_argument("IP", help="Target SMB server IP address")
    parser.add_argument("--os", choices=["unix", "windows"], help="Override target OS detection")
    parser.add_argument("-s", "--domain-sid", help="Override Windows domain SID discovery")
    parser.add_argument("-r", "--range", default="1000-1050", help="RID range to scan (default: 1000-1050)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10, max: 50)")
    parser.add_argument("--timeout", type=int, default=10, help="RPC timeout in seconds (default: 10, range: 5-60)")
    parser.add_argument("-b", "--batch-size", type=int, default=20, help="Batch size for Unix scans (default: 20, range: 1-100)")
    
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument("-u", "--users", action="store_true", help="Scan users only")
    scan_group.add_argument("-g", "--groups", action="store_true", help="Scan groups only")
    
    parser.add_argument("-U", "--username", help="Username for authentication")
    parser.add_argument("-P", "--password", help="Password (prompted if username provided without password)")
    
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed progress and debug info")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output (results only)")
    parser.add_argument("-o", "--output", help="Save results to file")
    
    args = parser.parse_args()
    
    try:
        ipaddress.ip_address(args.IP)
    except ValueError:
        print(f"{C.R}[!]{C.E} Error: Invalid IP address '{args.IP}'")
        sys.exit(1)
    
    try:
        validate_rid_range(args.range)
    except ValidationError as e:
        print(f"{C.R}[!]{C.E} Error: {e}")
        sys.exit(1)
    
    username = args.username or ""
    password = args.password or ""
    
    if username:
        try:
            validate_username(username)
        except ValidationError as e:
            print(f"{C.R}[!]{C.E} Error: {e}")
            sys.exit(1)
        
        if not password:
            try:
                password = getpass.getpass(f"Password for {username}: ")
            except KeyboardInterrupt:
                print(f"\n{C.R}[!]{C.E} Cancelled")
                sys.exit(1)
    
    if args.domain_sid:
        try:
            validate_domain_sid(args.domain_sid)
        except ValidationError as e:
            print(f"{C.R}[!]{C.E} Error: {e}")
            sys.exit(1)
    
    if args.output:
        try:
            validate_output_path(args.output)
        except ValidationError as e:
            print(f"{C.R}[!]{C.E} Error: {e}")
            sys.exit(1)
    
    if not 1 <= args.threads <= 50:
        print(f"{C.R}[!]{C.E} Error: Thread count must be between 1 and 50")
        sys.exit(1)
    
    if not 1 <= args.batch_size <= 100:
        print(f"{C.R}[!]{C.E} Error: Batch size must be between 1 and 100")
        sys.exit(1)
    
    if not 5 <= args.timeout <= 60:
        print(f"{C.R}[!]{C.E} Error: Timeout must be between 5 and 60 seconds")
        sys.exit(1)
    
    if args.verbose and args.quiet:
        print(f"{C.R}[!]{C.E} Error: Cannot specify both --verbose and --quiet")
        sys.exit(1)
    
    if args.users:
        scan_users, scan_groups = True, False
    elif args.groups:
        scan_users, scan_groups = False, True
    else:
        scan_users, scan_groups = True, True
    
    try:
        if not args.os:
            args.os, discovered_sid = detect_target_type(args.IP, username, password, args.verbose and not args.quiet)
            if args.os == "windows" and not args.domain_sid:
                args.domain_sid = discovered_sid
        
        if args.os == "windows" and not args.domain_sid:
            if args.verbose and not args.quiet:
                print(f"{C.Y}[*]{C.E} Auto-discovering Windows domain SID...", end="", flush=True)
            args.domain_sid = get_domain_sid(args.IP, username, password)
            if not args.domain_sid:
                print(f"\r{C.R}[!]{C.E} Error: Could not discover domain SID")
                sys.exit(1)
            elif args.verbose and not args.quiet:
                print(f"\r{C.G}[+]{C.E} Found domain SID: S-1-5-21-{args.domain_sid}")
    
    except AuthenticationError as e:
        print(f"{C.R}[!]{C.E} Authentication error: {e}")
        sys.exit(1)
    except NetworkError as e:
        print(f"{C.R}[!]{C.E} Network error: {e}")
        sys.exit(1)
    
    rid_list = parse_range(args.range)
    batch_size = args.batch_size if args.os == "unix" else 1
    rid_batches = [rid_list[i:i + batch_size] for i in range(0, len(rid_list), batch_size)]
    
    if not args.quiet:
        show_connection_status(args.IP, username, args.os, args.domain_sid)
        
        if args.verbose:
            scan_desc = "users and groups"
            if args.users:
                scan_desc = "users only"
            elif args.groups:
                scan_desc = "groups only"
            
            print(f"{C.Y}[*]{C.E} RID range: {min(rid_list)}-{max(rid_list)} ({len(rid_list)} RIDs)")
            print(f"{C.Y}[*]{C.E} Scanning: {scan_desc}")
            print(f"{C.Y}[*]{C.E} Using {args.threads} threads, batch size {batch_size}")
            print(f"{C.Y}[*]{C.E} Starting scan...\n")
    
    found_results = []
    start_time = time.time()
    completed_rids = 0
    error_count = 0
    header_shown = False
    
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(
                    scan_rid_batch, args.IP, batch, args.os, args.domain_sid, 
                    scan_users, scan_groups, username, password, args.timeout
                ): batch for batch in rid_batches
            }
            
            for future in as_completed(futures):
                batch = futures[future]
                completed_rids += len(batch)
                
                try:
                    results = future.result()
                    
                    for rid, obj_type, name in results:
                        found_results.append((rid, obj_type, name))
                        
                        if args.verbose and not args.quiet:
                            print(f"{C.G}[+]{C.E} RID {rid}: {obj_type.lower()} '{name}'")
                        elif not args.quiet:
                            if not header_shown:
                                print(f"\n{'RID':<6} {'Type':<6} {'Name'}")
                                print("-" * 50)
                                header_shown = True
                            print(f"{rid:<6} {obj_type:<6} {name}")
                        else:
                            print(f"{rid}:{obj_type}:{name}")
                
                except Exception as e:
                    error_count += len(batch)
                    if args.verbose and not args.quiet:
                        print(f"{C.R}[!]{C.E} Batch error for RIDs {batch[0]}-{batch[-1]}: {e}")
    
    except KeyboardInterrupt:
        if not args.quiet:
            print(f"{C.R}[!]{C.E} Scan interrupted after {completed_rids}/{len(rid_list)} RIDs")
            if found_results:
                print(f"{C.Y}[*]{C.E} Partial results: {len(found_results)} objects found")
        sys.exit(1)
    
    elapsed = time.time() - start_time
    found_results.sort()
    
    if args.verbose and not args.quiet:
        show_performance_summary(len(rid_list), len(found_results), error_count, elapsed)
    
    if args.output and found_results:
        try:
            with open(args.output, 'w') as f:
                f.write(f"{'RID':<6} {'Type':<6} {'Name'}\n")
                f.write("-" * 50 + "\n")
                for rid, obj_type, name in found_results:
                    f.write(f"{rid:<6} {obj_type:<6} {name}\n")
            if not args.quiet:
                print(f"{C.Y}[*]{C.E} Results saved to {args.output}")
        except IOError as e:
            print(f"{C.R}[!]{C.E} Error saving file: {e}")
        except OSError as e:
            print(f"{C.R}[!]{C.E} File system error: {e}")

if __name__ == "__main__":
    main()
