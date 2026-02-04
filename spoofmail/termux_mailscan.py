#!/usr/bin/env python3
"""
Network Security Tools Suite v4.0 - TERMUX ANDROID EDITION
-----------------------------------------------------------
Mobile-optimized for Termux on Android
Path: /storage/6BF7-FF88/Android/data/com.termux/files/termux_distro/spoofmail/
"""

import os
import sys
import re
import json
import socket
import ssl
import subprocess
import time
import requests
import hashlib
import mimetypes
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Install and import rich for better display
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
except ImportError:
    print("Installing rich library...")
    os.system('pip install rich requests')
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

# ============================================================================
# TERMUX PATH CONFIGURATION
# ============================================================================

BASE_DIR = Path("/storage/6BF7-FF88/Android/data/com.termux/files/termux_distro/spoofmail")

# Create directory if it doesn't exist
try:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
except Exception as e:
    console.print(f"[yellow]Warning: {e}[/yellow]")
    BASE_DIR = Path.cwd()

# All files save to your specified path
HISTORY_FILE = BASE_DIR / ".network_tools_history.json"
CACHE_FILE = BASE_DIR / ".network_tools_cache.json"
REPORTS_DIR = BASE_DIR / "security_reports"
REPORTS_DIR.mkdir(exist_ok=True)

console.print(f"[green]✓ Base directory: {BASE_DIR}[/green]")
console.print(f"[green]✓ Reports folder: {REPORTS_DIR}[/green]\n")

# Load API key from .env file in same directory
try:
    from dotenv import load_dotenv
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=True)
        console.print(f"[green]✓ Loaded .env from {env_path}[/green]\n")
    else:
        console.print(f"[yellow]⚠️ No .env file found at {env_path}[/yellow]\n")
except Exception as e:
    console.print(f"[yellow]⚠️ Could not load .env: {e}[/yellow]\n")

# ============================================================================
# COMMON ANDROID/TERMUX PATHS
# ============================================================================

COMMON_PATHS = {
    "Internal Storage": Path("/storage/emulated/0"),
    "Download": Path("/storage/emulated/0/Download"),
    "Documents": Path("/storage/emulated/0/Documents"),
    "DCIM (Camera)": Path("/storage/emulated/0/DCIM"),
    "Pictures": Path("/storage/emulated/0/Pictures"),
    "SD Card": Path("/storage/6BF7-FF88"),
    "Termux Home": Path.home(),
    "Current Directory": Path.cwd(),
}

# ============================================================================
# CORE FUNCTIONS
# ============================================================================

def get_vt_api_key():
    key = os.getenv("VT_API_KEY", "").strip()
    if key:
        console.print(f"[green]✓ VT API Key loaded: {key[:8]}...{key[-4:]}[/green]")
    return key

def load_cache():
    try:
        if CACHE_FILE.exists():
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_cache(cache_data):
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_data, f, indent=2, default=str)
    except:
        pass

def save_to_history(tool_name, result):
    try:
        history = []
        if HISTORY_FILE.exists():
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
        history.insert(0, {
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "result": result
        })
        history = history[:100]
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2, default=str)
    except:
        pass

def clear_screen():
    os.system('clear')

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════╗
    ║   DNS • Email • Domain • File Scanner     ║
    ║      Frank Net Tools v4.0 (Termux)        ║
    ╚═══════════════════════════════════════════╝
    """
    console.print(banner, style="cyan bold")

def press_enter():
    input("\nPress ENTER to continue...")

# ============================================================================
# FILE BROWSER FOR TERMUX
# ============================================================================

def browse_files():
    """Interactive file browser for easy file selection"""
    clear_screen()
    console.print(Panel("[cyan bold]File Browser[/cyan bold]", border_style="cyan"))
    
    console.print("\n[yellow]Select a location:[/yellow]\n")
    
    # Show common paths
    paths_list = []
    for i, (name, path) in enumerate(COMMON_PATHS.items(), 1):
        exists = "✓" if path.exists() else "✗"
        color = "green" if path.exists() else "red"
        console.print(f"  [{color}]{i}. {exists} {name}[/{color}]")
        console.print(f"     {path}\n")
        paths_list.append(path)
    
    console.print(f"  0. Enter custom path")
    console.print(f"  9. Cancel\n")
    
    choice = input("Select location (0-9): ").strip()
    
    if choice == '9':
        return None
    elif choice == '0':
        custom_path = input("\nEnter full path: ").strip().strip('"').strip("'")
        if custom_path:
            selected_path = Path(custom_path)
        else:
            return None
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(paths_list):
                selected_path = paths_list[idx]
            else:
                console.print("[red]Invalid choice[/red]")
                time.sleep(1)
                return None
        except:
            console.print("[red]Invalid input[/red]")
            time.sleep(1)
            return None
    
    if not selected_path.exists():
        console.print(f"[red]Path does not exist: {selected_path}[/red]")
        time.sleep(2)
        return None
    
    # List files in selected directory
    clear_screen()
    console.print(Panel(f"[cyan]Files in: {selected_path}[/cyan]", border_style="cyan"))
    
    try:
        files = []
        dirs = []
        
        for item in selected_path.iterdir():
            if item.is_file():
                files.append(item)
            elif item.is_dir():
                dirs.append(item)
        
        # Sort
        dirs.sort()
        files.sort()
        
        # Show directories first
        console.print("\n[yellow bold]Directories:[/yellow bold]")
        dir_list = []
        for i, d in enumerate(dirs[:20], 1):  # Show max 20 dirs
            console.print(f"  {i}. 📁 {d.name}")
            dir_list.append(d)
        
        if not dirs:
            console.print("  [dim](no subdirectories)[/dim]")
        elif len(dirs) > 20:
            console.print(f"  [dim]... and {len(dirs)-20} more[/dim]")
        
        # Show files
        console.print("\n[yellow bold]Files:[/yellow bold]")
        file_list = []
        for i, f in enumerate(files[:30], 1):  # Show max 30 files
            size_mb = f.stat().st_size / (1024 * 1024)
            if size_mb < 1:
                size_str = f"{f.stat().st_size / 1024:.1f}KB"
            else:
                size_str = f"{size_mb:.2f}MB"
            console.print(f"  {i+len(dir_list)}. 📄 {f.name} ({size_str})")
            file_list.append(f)
        
        if not files:
            console.print("  [dim](no files)[/dim]")
        elif len(files) > 30:
            console.print(f"  [dim]... and {len(files)-30} more files[/dim]")
        
        console.print("\n  0. Enter file name manually")
        console.print("  9. Go back\n")
        
        choice = input("Select file/directory (0-9 or number): ").strip()
        
        if choice == '9':
            return browse_files()
        elif choice == '0':
            filename = input("Enter filename: ").strip()
            return selected_path / filename
        else:
            try:
                idx = int(choice) - 1
                # Check if it's a directory
                if idx < len(dir_list):
                    # Navigate into directory
                    new_path = dir_list[idx]
                    COMMON_PATHS["Selected Directory"] = new_path
                    return browse_files()
                # It's a file
                elif idx < len(dir_list) + len(file_list):
                    file_idx = idx - len(dir_list)
                    return file_list[file_idx]
                else:
                    console.print("[red]Invalid selection[/red]")
                    time.sleep(1)
                    return browse_files()
            except:
                console.print("[red]Invalid input[/red]")
                time.sleep(1)
                return browse_files()
    
    except PermissionError:
        console.print(f"[red]Permission denied: {selected_path}[/red]")
        time.sleep(2)
        return browse_files()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        time.sleep(2)
        return browse_files()

# ============================================================================
# DNS AND NETWORK FUNCTIONS (ENHANCED)
# ============================================================================

def check_dns_exists(domain):
    try:
        ip = socket.gethostbyname(domain)
        return True, f"Resolves to {ip}", ip
    except:
        return False, "DNS lookup failed", None

def check_mx_records(domain):
    try:
        import dns.resolver
        mx = dns.resolver.resolve(domain, 'MX')
        return True, f"Found {len(mx)} MX records", [str(r.exchange) for r in mx]
    except ImportError:
        return None, "Install: pkg install python-dnspython", []
    except:
        return False, "No MX records", []

def check_spf_record(domain):
    try:
        import dns.resolver
        for record in dns.resolver.resolve(domain, 'TXT'):
            if 'v=spf1' in str(record).lower():
                return True, "SPF found", str(record)
        return False, "No SPF", None
    except:
        return False, "Could not check", None

def check_dmarc_record(domain):
    try:
        import dns.resolver
        for record in dns.resolver.resolve(f"_dmarc.{domain}", 'TXT'):
            if 'v=DMARC1' in str(record):
                return True, "DMARC found", str(record)
        return False, "No DMARC", None
    except:
        return False, "No DMARC", None

def check_https_redirect(domain):
    try:
        resp = requests.get(f"http://{domain}", timeout=10, allow_redirects=True)
        return resp.url.startswith("https://"), "HTTPS redirect" if resp.url.startswith("https://") else "No redirect"
    except:
        return False, "Check failed"

def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', []))
                not_after = cert.get('notAfter')
                valid_until = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_remaining = (valid_until - datetime.now()).days
                return {
                    "valid": True,
                    "subject": subject.get('commonName', 'Unknown'),
                    "days_remaining": days_remaining,
                    "tls_version": ssock.version()
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}

def check_domain_age(domain):
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", 
                           headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        if resp.status_code == 200:
            for event in resp.json().get("events", []):
                if event.get("eventAction") == "registration":
                    reg_date = datetime.fromisoformat(event.get("eventDate").replace('Z', '+00:00'))
                    age_years = (datetime.now() - reg_date.replace(tzinfo=None)).days / 365.25
                    return {
                        "found": True,
                        "registered": reg_date.strftime('%Y-%m-%d'),
                        "age_years": round(age_years, 1)
                    }
        return {"found": False}
    except:
        return {"found": False}

def check_disposable_email(domain):
    disposable = {'tempmail.com', 'guerrillamail.com', 'mailinator.com', 
                  '10minutemail.com', 'throwaway.email', 'yopmail.com'}
    return domain.lower() in disposable, "Disposable" if domain.lower() in disposable else "Not disposable"

def detect_typosquatting(domain):
    brands = ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'netflix']
    domain_name = domain.split('.')[0].lower()
    matches = []
    for brand in brands:
        if brand in domain_name and brand != domain_name:
            matches.append(f"Contains '{brand}'")
    return matches

def analyze_domain_heuristics(domain):
    risk = 0
    warnings = []
    if domain.endswith(('.xyz', '.top', '.work', '.click')):
        risk += 25
        warnings.append("High-risk TLD")
    if domain.count('-') >= 3:
        risk += 20
        warnings.append(f"Excessive hyphens ({domain.count('-')})")
    typo = detect_typosquatting(domain)
    if typo:
        risk += 30
        warnings.extend(typo)
    return min(risk, 100), warnings

def check_virustotal_reputation(domain):
    vt_key = get_vt_api_key()
    cache = load_cache()
    cache_key = f"vt_{domain}"
    
    if cache_key in cache:
        cached = cache[cache_key]
        cache_time = datetime.fromisoformat(cached['timestamp'])
        if (datetime.now() - cache_time).total_seconds() < 86400:
            console.print("[yellow]Using cached result[/yellow]")
            return cached['status'], cached['message'], cached['data']
    
    if not vt_key:
        risk, _ = analyze_domain_heuristics(domain)
        if risk >= 50:
            return "HIGH RISK", "Heuristic flags", None
        return "OK", "No API key", None
    
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                           headers={"x-apikey": vt_key}, timeout=10)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            sus = stats.get("suspicious", 0)
            total = sum(stats.values())
            
            if mal > 0:
                status, msg = f"MALICIOUS ({mal}/{total})", f"{mal} vendors flagged"
            elif sus > 0:
                status, msg = f"SUSPICIOUS ({sus}/{total})", f"{sus} vendors flagged"
            else:
                status, msg = f"CLEAN ({total})", "No threats"
            
            vt_data = {"malicious": mal, "suspicious": sus, "total": total}
            cache[cache_key] = {
                "timestamp": datetime.now().isoformat(),
                "status": status,
                "message": msg,
                "data": vt_data
            }
            save_cache(cache)
            return status, msg, vt_data
        return "NOT IN DB", "Not found", None
    except:
        return "ERROR", "Check failed", None

def calculate_risk_score(results):
    risk = 0
    if not results.get('dns'): risk += 30
    if not results.get('ssl'): risk += 15
    if results.get('disposable'): risk += 25
    age = results.get('age', {})
    if age.get('found') and age.get('age_years', 999) < 1: risk += 20
    risk += results.get('heuristic', 0) * 0.3
    vt = results.get('virustotal')
    if vt and vt.get('malicious', 0) > 0: risk += 50
    return min(int(risk), 100)

# ============================================================================
# VIRUSTOTAL FILE SCANNING
# ============================================================================

def get_virustotal_file_report(file_hash):
    vt_key = get_vt_api_key()
    if not vt_key: return None
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}",
                           headers={"x-apikey": vt_key}, timeout=10)
        return resp.json() if resp.status_code == 200 else None
    except:
        return None

def upload_file_to_virustotal(filepath):
    vt_key = get_vt_api_key()
    if not vt_key: return None, "No API key"
    
    file_size = os.path.getsize(filepath)
    if file_size > 32 * 1024 * 1024:
        return None, f"File too large ({file_size/(1024*1024):.1f}MB)"
    
    try:
        with open(filepath, 'rb') as f:
            resp = requests.post("https://www.virustotal.com/api/v3/files",
                               headers={"x-apikey": vt_key},
                               files={"file": (os.path.basename(filepath), f)},
                               timeout=300)
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("id"), "Upload successful"
        return None, f"Upload failed: {resp.status_code}"
    except Exception as e:
        return None, str(e)

def wait_for_analysis(analysis_id):
    vt_key = get_vt_api_key()
    if not vt_key: return None
    
    with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing...[/cyan]"), console=console) as progress:
        task = progress.add_task("", total=None)
        for _ in range(60):
            try:
                resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                   headers={"x-apikey": vt_key}, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("data", {}).get("attributes", {}).get("status") == "completed":
                        file_id = data.get("meta", {}).get("file_info", {}).get("sha256")
                        return get_virustotal_file_report(file_id) if file_id else data
                time.sleep(5)
            except:
                time.sleep(5)
    return None

def parse_vt_file_results(vt_data):
    if not vt_data: return None
    try:
        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})
        
        detections = []
        for vendor, result in results.items():
            if result.get("category") in ["malicious", "suspicious"]:
                detections.append({
                    "vendor": vendor,
                    "category": result.get("category"),
                    "result": result.get("result", "Unknown")
                })
        
        return {
            "stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total": sum(stats.values())
            },
            "detections": detections,
            "file_info": {
                "sha256": attrs.get("sha256", "N/A"),
                "size": attrs.get("size", 0),
                "type": attrs.get("type_description", "Unknown")
            }
        }
    except:
        return None

def export_json_report(original_input, domain, input_type, results, risk_score, warnings):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = REPORTS_DIR / f"report_{domain}_{timestamp}.json"
    
    data = {
        "scan_time": datetime.now().isoformat(),
        "input": original_input,
        "domain": domain,
        "type": input_type,
        "risk_score": risk_score,
        "results": results,
        "warnings": warnings
    }
    
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        console.print(f"[green]✓ Saved: {filename}[/green]")
        return str(filename)
    except Exception as e:
        console.print(f"[red]Export failed: {e}[/red]")
        return None

# ============================================================================
# TOOLS (ENHANCED)
# ============================================================================

def dns_lookup_tool():
    """Enhanced DNS Lookup with full details like Windows version"""
    clear_screen()
    console.print(Panel("[cyan bold]🌐 Global DNS Lookup Tool[/cyan bold]", border_style="cyan"))
    domain = input("\nEnter domain to lookup: ").strip()
    if not domain: 
        console.print("[red]No domain provided[/red]")
        press_enter()
        return
    
    console.print(f"\n[cyan]Performing DNS lookup for: {domain}[/cyan]\n")
    
    results = {}
    
    # A Records (IPv4)
    try:
        a_records = socket.gethostbyname_ex(domain)
        results['A'] = a_records[2]
        console.print(f"[green bold]A Records (IPv4):[/green bold]")
        for ip in a_records[2]:
            console.print(f"  → {ip}")
    except Exception as e:
        console.print(f"[red]A Records: {str(e)}[/red]")
    
    console.print()
    
    # Check if dnspython is installed
    try:
        import dns.resolver
        
        # MX Records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            results['MX'] = [str(r.exchange) for r in mx_records]
            console.print(f"[green bold]MX Records (Mail Servers):[/green bold]")
            for mx in sorted(mx_records, key=lambda x: x.preference):
                console.print(f"  → Priority {mx.preference}: {mx.exchange}")
        except dns.resolver.NoAnswer:
            console.print(f"[yellow]MX Records: Not found[/yellow]")
        except Exception as e:
            console.print(f"[yellow]MX Records: {str(e)}[/yellow]")
        
        console.print()
        
        # TXT Records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            results['TXT'] = [str(r) for r in txt_records]
            console.print(f"[green bold]TXT Records:[/green bold]")
            for txt in txt_records:
                txt_str = str(txt)
                # Show SPF/DMARC in full, truncate others
                if 'v=spf1' in txt_str.lower() or 'v=DMARC1' in txt_str.upper():
                    console.print(f"  → {txt_str}")
                elif len(txt_str) > 80:
                    console.print(f"  → {txt_str[:77]}...")
                else:
                    console.print(f"  → {txt_str}")
        except dns.resolver.NoAnswer:
            console.print(f"[yellow]TXT Records: Not found[/yellow]")
        except Exception as e:
            console.print(f"[yellow]TXT Records: {str(e)}[/yellow]")
        
        console.print()
        
        # NS Records (Name Servers)
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            results['NS'] = [str(r) for r in ns_records]
            console.print(f"[green bold]NS Records (Name Servers):[/green bold]")
            for ns in ns_records:
                console.print(f"  → {ns}")
        except dns.resolver.NoAnswer:
            console.print(f"[yellow]NS Records: Not found[/yellow]")
        except Exception as e:
            console.print(f"[yellow]NS Records: {str(e)}[/yellow]")
        
        console.print()
        
        # AAAA Records (IPv6)
        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            results['AAAA'] = [str(r) for r in aaaa_records]
            console.print(f"[green bold]AAAA Records (IPv6):[/green bold]")
            for ipv6 in aaaa_records:
                console.print(f"  → {ipv6}")
        except dns.resolver.NoAnswer:
            console.print(f"[yellow]AAAA Records: Not found (IPv6 not configured)[/yellow]")
        except Exception as e:
            console.print(f"[yellow]AAAA Records: {str(e)}[/yellow]")
        
        console.print()
        
        # CNAME Records
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            results['CNAME'] = [str(r) for r in cname_records]
            console.print(f"[green bold]CNAME Records:[/green bold]")
            for cname in cname_records:
                console.print(f"  → {cname}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            console.print(f"[dim]CNAME Records: Not found (domain is not an alias)[/dim]")
        except Exception as e:
            console.print(f"[yellow]CNAME Records: {str(e)}[/yellow]")
    
    except ImportError:
        console.print(f"[yellow bold]⚠️ Install dnspython for more record types:[/yellow bold]")
        console.print(f"[yellow]   pkg install python-dnspython[/yellow]")
        console.print(f"[yellow]   OR: pip install dnspython[/yellow]")
    
    save_to_history("DNS Lookup", {"domain": domain, "results": results})
    press_enter()

def ping_tool():
    """Enhanced Ping Tool - Fixed for Termux"""
    clear_screen()
    console.print(Panel("[cyan bold]📡 Ping IP Address Tool[/cyan bold]", border_style="cyan"))
    
    target = input("\nEnter IP address or domain: ").strip()
    if not target:
        console.print("[red]No target provided[/red]")
        press_enter()
        return
    
    count = input("Number of pings (default 4): ").strip()
    try:
        count = int(count) if count else 4
        count = max(1, min(count, 100))
    except:
        count = 4
    
    console.print(f"\n[cyan]Pinging {target} with {count} packets...[/cyan]\n")
    
    # Termux/Linux uses -c for count
    try:
        # Run ping command
        result = subprocess.run(
            ['ping', '-c', str(count), target],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            console.print("[green bold]✅ Host is reachable[/green bold]\n")
            
            # Parse and display output
            lines = result.stdout.split('\n')
            
            # Display each ping response
            for line in lines:
                if 'bytes from' in line.lower() or 'time=' in line.lower():
                    # Highlight the important parts
                    if 'time=' in line:
                        console.print(f"  [green]{line.strip()}[/green]")
                    else:
                        console.print(f"  {line.strip()}")
            
            save_to_history("Ping", {"target": target, "count": count, "status": "success"})
        else:
            console.print("[red bold]❌ Host is unreachable or request timed out[/red bold]")
            if result.stderr:
                console.print(f"[red]Error: {result.stderr.strip()}[/red]")
            save_to_history("Ping", {"target": target, "count": count, "status": "failed"})
    
    except subprocess.TimeoutExpired:
        console.print("[red]❌ Ping timed out (30 seconds)[/red]")
    except FileNotFoundError:
        console.print("[red]❌ Ping command not found[/red]")
        console.print("[yellow]Try: pkg install inetutils[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")
    
    press_enter()

def email_domain_checker():
    clear_screen()
    console.print(Panel("[cyan]Email & Domain Trust Checker[/cyan]", border_style="cyan"))
    user_input = input("\nEmail/Domain/URL: ").strip()
    if not user_input: return
    
    # Parse input
    if "@" in user_input:
        domain = user_input.split('@')[-1]
        input_type = "email"
    elif user_input.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        domain = urlparse(user_input).netloc.replace("www.", "")
        input_type = "url"
    else:
        domain = user_input
        input_type = "domain"
    
    console.print(f"\n[green]Analyzing: {domain}[/green]\n")
    
    # Run checks
    results = {}
    table = Table(title=f"Security Analysis: {domain}", border_style="cyan")
    table.add_column("Check", style="cyan", width=25)
    table.add_column("Status", width=35)
    
    # DNS
    dns_ok, dns_msg, _ = check_dns_exists(domain)
    results['dns'] = dns_ok
    table.add_row("DNS Resolution", f"[green]✓ {dns_msg}[/green]" if dns_ok else f"[red]✗ {dns_msg}[/red]")
    
    # SSL
    ssl_info = check_ssl_certificate(domain)
    results['ssl'] = ssl_info.get('valid')
    if ssl_info.get('valid'):
        table.add_row("SSL Certificate", f"[green]✓ Valid ({ssl_info['days_remaining']}d)[/green]")
    else:
        table.add_row("SSL Certificate", f"[yellow]? {ssl_info.get('error', 'N/A')}[/yellow]")
    
    # Domain Age
    age_info = check_domain_age(domain)
    results['age'] = age_info
    if age_info.get('found'):
        color = "green" if age_info['age_years'] >= 1 else "yellow"
        table.add_row("Domain Age", f"[{color}]{age_info['age_years']}y ({age_info['registered']})[/{color}]")
    else:
        table.add_row("Domain Age", "[yellow]? Unknown[/yellow]")
    
    # Heuristics
    risk_score, warnings = analyze_domain_heuristics(domain)
    results['heuristic'] = risk_score
    results['warnings'] = warnings
    color = "red" if risk_score >= 50 else "yellow" if risk_score >= 25 else "green"
    table.add_row("Heuristic Risk", f"[{color}]{risk_score}/100[/{color}]")
    
    # VirusTotal
    vt_status, vt_msg, vt_data = check_virustotal_reputation(domain)
    results['virustotal'] = vt_data
    table.add_row("VirusTotal", f"{vt_msg}")
    
    console.print(table)
    
    if warnings:
        console.print(f"\n[yellow]Warnings:[/yellow]")
        for w in warnings:
            console.print(f"  • {w}")
    
    # Final verdict
    overall_risk = calculate_risk_score(results)
    if overall_risk >= 70:
        verdict = "[red]🚨 HIGH RISK[/red]"
    elif overall_risk >= 50:
        verdict = "[yellow]⚠️ SUSPICIOUS[/yellow]"
    else:
        verdict = "[green]✓ Appears Safe[/green]"
    
    console.print(f"\n{verdict} - Risk Score: {overall_risk}/100\n")
    
    # Export
    if input("Export report? (y/N): ").lower() == 'y':
        export_json_report(user_input, domain, input_type, results, overall_risk, warnings)
    
    save_to_history("Domain Checker", {"domain": domain, "risk": overall_risk})
    press_enter()

def file_scanner_tool():
    """Enhanced File Scanner with file browser"""
    clear_screen()
    console.print(Panel("[cyan bold]🦠 File Scanner (VirusTotal)[/cyan bold]", border_style="cyan"))
    
    if not get_vt_api_key():
        console.print("\n[red bold]❌ VirusTotal API key required![/red bold]")
        console.print("[yellow]Get free key: https://www.virustotal.com/gui/my-apikey[/yellow]")
        console.print(f"[yellow]Save to: {BASE_DIR}/.env[/yellow]")
        console.print(f"[yellow]Format: VT_API_KEY=your_key_here[/yellow]")
        press_enter()
        return
    
    console.print("\n[yellow]Choose input method:[/yellow]")
    console.print("  1. Browse files (recommended)")
    console.print("  2. Enter file path manually")
    console.print("  3. Cancel\n")
    
    choice = input("Choice (1-3): ").strip()
    
    if choice == '1':
        filepath = browse_files()
        if not filepath:
            console.print("[yellow]No file selected[/yellow]")
            press_enter()
            return
    elif choice == '2':
        filepath_input = input("\nEnter file path: ").strip().strip('"').strip("'")
        if not filepath_input:
            console.print("[red]No path provided[/red]")
            press_enter()
            return
        filepath = Path(filepath_input)
    else:
        return
    
    if not filepath.exists():
        console.print(f"[red]❌ File not found: {filepath}[/red]")
        press_enter()
        return
    
    if not filepath.is_file():
        console.print(f"[red]❌ Path is not a file: {filepath}[/red]")
        press_enter()
        return
    
    file_size = filepath.stat().st_size / (1024 * 1024)
    console.print(f"\n[cyan]📁 File: {filepath.name}[/cyan]")
    console.print(f"[cyan]📊 Size: {file_size:.2f}MB[/cyan]")
    console.print(f"[cyan]📍 Path: {filepath}[/cyan]\n")
    
    # Calculate hash
    console.print("[cyan]🔍 Calculating file hash...[/cyan]")
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            if file_size > 10:  # Show progress for files > 10MB
                with Progress(
                    SpinnerColumn(),
                    TextColumn(f"[cyan]Hashing {file_size:.1f}MB file..."),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=console
                ) as progress:
                    file_size_bytes = filepath.stat().st_size
                    task = progress.add_task("", total=file_size_bytes)
                    bytes_read = 0
                    for chunk in iter(lambda: f.read(8192), b""):
                        sha256.update(chunk)
                        bytes_read += len(chunk)
                        progress.update(task, completed=bytes_read)
            else:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
        
        file_hash = sha256.hexdigest()
        console.print(f"[green]✅ SHA-256: {file_hash}[/green]\n")
    except Exception as e:
        console.print(f"[red]❌ Hash calculation failed: {e}[/red]")
        press_enter()
        return
    
    # Check VT database
    console.print("[cyan]🔍 Checking VirusTotal database...[/cyan]")
    vt_data = get_virustotal_file_report(file_hash)
    
    if not vt_data:
        console.print("[yellow]⚠️ File not in database. Uploading...[/yellow]")
        analysis_id, msg = upload_file_to_virustotal(str(filepath))
        if not analysis_id:
            console.print(f"[red]❌ {msg}[/red]")
            press_enter()
            return
        console.print(f"[green]✅ {msg}[/green]")
        vt_data = wait_for_analysis(analysis_id)
    else:
        console.print("[green]✅ Found in database! Using cached results.[/green]")
    
    if not vt_data:
        console.print("[red]❌ Analysis failed or timed out[/red]")
        press_enter()
        return
    
    # Parse results
    parsed = parse_vt_file_results(vt_data)
    if not parsed:
        console.print("[red]❌ Could not parse results[/red]")
        press_enter()
        return
    
    stats = parsed['stats']
    
    # Display results
    console.print(f"\n[bold]Scan Results:[/bold]")
    console.print(f"[red]Malicious: {stats['malicious']}[/red] | "
                 f"[yellow]Suspicious: {stats['suspicious']}[/yellow] | "
                 f"[green]Clean: {stats['harmless']}[/green]")
    console.print(f"Total Engines: {stats['total']}\n")
    
    if stats['malicious'] > 0:
        console.print("[red bold]🚨 THREAT DETECTED - DO NOT EXECUTE[/red bold]")
    elif stats['suspicious'] > 0:
        console.print("[yellow bold]⚠️ SUSPICIOUS FILE[/yellow bold]")
    else:
        console.print("[green bold]✅ FILE APPEARS CLEAN[/green bold]")
    
    if parsed['detections'] and stats['malicious'] > 0:
        console.print(f"\n[red bold]⚠️ Top Detections:[/red bold]")
        for i, det in enumerate(parsed['detections'][:10], 1):
            console.print(f"  {i}. [yellow]{det['vendor']}[/yellow]: {det['result']}")
        
        if len(parsed['detections']) > 10:
            console.print(f"  [dim]... and {len(parsed['detections'])-10} more detections[/dim]")
    
    save_to_history("File Scanner", {
        "file": filepath.name,
        "path": str(filepath),
        "hash": file_hash,
        "malicious": stats['malicious']
    })
    press_enter()

def view_history():
    clear_screen()
    console.print(Panel("[cyan]History[/cyan]", border_style="cyan"))
    
    if not HISTORY_FILE.exists():
        console.print("\n[yellow]No history[/yellow]")
        press_enter()
        return
    
    with open(HISTORY_FILE) as f:
        history = json.load(f)
    
    table = Table(title="Recent Activity", border_style="cyan")
    table.add_column("#", width=4)
    table.add_column("Time", width=18)
    table.add_column("Tool", width=20)
    table.add_column("Target", width=25)
    
    for i, entry in enumerate(history[:15], 1):
        dt = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M')
        tool = entry['tool']
        result = entry.get('result', {})
        target = result.get('domain') or result.get('target') or result.get('file') or 'N/A'
        table.add_row(str(i), dt, tool, target[:23])
    
    console.print(table)
    console.print(f"\n[cyan]Files: {HISTORY_FILE}[/cyan]")
    press_enter()

def clear_cache_tool():
    clear_screen()
    console.print(Panel("[cyan]Clear Cache[/cyan]", border_style="cyan"))
    
    console.print("\n1. Cache only")
    console.print("2. History only")
    console.print("3. Both")
    
    choice = input("\nChoice (1-3): ").strip()
    
    if choice == '1' and CACHE_FILE.exists():
        CACHE_FILE.unlink()
        console.print("[green]✓ Cache cleared[/green]")
    elif choice == '2' and HISTORY_FILE.exists():
        HISTORY_FILE.unlink()
        console.print("[green]✓ History cleared[/green]")
    elif choice == '3':
        if CACHE_FILE.exists(): CACHE_FILE.unlink()
        if HISTORY_FILE.exists(): HISTORY_FILE.unlink()
        console.print("[green]✓ All cleared[/green]")
    
    press_enter()

# ============================================================================
# MAIN MENU
# ============================================================================

def show_main_menu():
    clear_screen()
    print_banner()
    
    console.print(Panel("[white]Professional Security Tools for Android[/white]", border_style="cyan"))
    
    console.print("\n[cyan]1.[/cyan] DNS Lookup")
    console.print("[cyan]2.[/cyan] Ping Tool")
    console.print("[cyan]3.[/cyan] Email & Domain Trust Checker")
    console.print("[cyan]4.[/cyan] File Scanner (VirusTotal)")
    console.print("[cyan]5.[/cyan] View History")
    console.print("[cyan]6.[/cyan] Clear Cache")
    console.print("[cyan]7.[/cyan] Exit\n")
    
    return input("Choice (1-7): ").strip()

def main():
    # Check dependencies
    try:
        import dns.resolver
    except ImportError:
        console.print("[yellow]⚠️ For full DNS features, install:[/yellow]")
        console.print("[yellow]   pkg install python-dnspython[/yellow]\n")
        time.sleep(2)
    
    while True:
        try:
            choice = show_main_menu()
            
            if choice == '1': dns_lookup_tool()
            elif choice == '2': ping_tool()
            elif choice == '3': email_domain_checker()
            elif choice == '4': file_scanner_tool()
            elif choice == '5': view_history()
            elif choice == '6': clear_cache_tool()
            elif choice == '7':
                console.print("\n[cyan bold]Paalam! 👋[/cyan bold]\n")
                break
            else:
                console.print("[red]Invalid choice[/red]")
                time.sleep(1)
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted[/yellow]")
            if input("Exit? (y/N): ").lower() == 'y':
                break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            press_enter()

if __name__ == "__main__":
    main()