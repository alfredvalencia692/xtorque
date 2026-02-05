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
# ENHANCED COMMON ANDROID/TERMUX PATHS (UPDATED)
# ============================================================================

COMMON_PATHS = {
    "Internal Storage": Path("/storage/emulated/0"),
    "Download (Internal)": Path("/storage/emulated/0/Download"),
    "Documents (Internal)": Path("/storage/emulated/0/Documents"),
    "DCIM (Internal)": Path("/storage/emulated/0/DCIM"),
    "Pictures (Internal)": Path("/storage/emulated/0/Pictures"),
    "SD Card Root": Path("/storage/6BF7-FF88"),
    "Download (SD Card)": Path("/storage/6BF7-FF88/Download"),
    "DCIM (SD Card)": Path("/storage/6BF7-FF88/DCIM"),
    "Pictures (SD Card)": Path("/storage/6BF7-FF88/Pictures"),
    "Documents (SD Card)": Path("/storage/6BF7-FF88/Documents"),
    "Music (SD Card)": Path("/storage/6BF7-FF88/Music"),
    "Movies (SD Card)": Path("/storage/6BF7-FF88/Movies"),
    "Android (SD Card)": Path("/storage/6BF7-FF88/Android"),
    "Termux Home": Path.home(),
    "Current Directory": Path.cwd(),
}

# Quarantine directory
QUARANTINE_DIR = BASE_DIR / "quarantine"
QUARANTINE_DIR.mkdir(exist_ok=True)
QUARANTINE_DB = BASE_DIR / ".quarantine_db.json"

# ============================================================================
# TERMUX DNS FIX
# ============================================================================

def setup_termux_dns():
    """Fix DNS resolution for Termux environment"""
    try:
        import dns.resolver
        
        # Set Google's public DNS servers as default for Termux
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = [
            '8.8.8.8',      # Google DNS
            '8.8.4.4',      # Google DNS Secondary
            '1.1.1.1',      # Cloudflare DNS
            '1.0.0.1'       # Cloudflare DNS Secondary
        ]
        return True
    except ImportError:
        return False
    except Exception as e:
        console.print(f"[yellow]DNS setup warning: {e}[/yellow]")
        return False

# Call this at the start of main()

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

# ============================================================================
# QUARANTINE MANAGEMENT FUNCTIONS
# ============================================================================

def load_quarantine_db():
    """Load quarantine database"""
    try:
        if QUARANTINE_DB.exists():
            with open(QUARANTINE_DB, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_quarantine_db(db):
    """Save quarantine database"""
    try:
        with open(QUARANTINE_DB, 'w') as f:
            json.dump(db, f, indent=2, default=str)
    except Exception as e:
        console.print(f"[red]Failed to save quarantine DB: {e}[/red]")

def quarantine_file(filepath, scan_results):
    """Move infected file to quarantine"""
    try:
        filepath = Path(filepath)
        
        # Generate unique quarantine filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        quarantine_name = f"{timestamp}_{filepath.name}"
        quarantine_path = QUARANTINE_DIR / quarantine_name
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Save to quarantine (encrypted with simple XOR to prevent accidental execution)
        with open(quarantine_path, 'wb') as f:
            # Simple XOR obfuscation with key 0xAA
            encrypted = bytes([b ^ 0xAA for b in file_content])
            f.write(encrypted)
        
        # Load quarantine database
        qdb = load_quarantine_db()
        
        # Add to database
        qdb[quarantine_name] = {
            "original_path": str(filepath.absolute()),
            "original_name": filepath.name,
            "quarantine_date": datetime.now().isoformat(),
            "file_size": len(file_content),
            "sha256": scan_results.get('hash', 'unknown'),
            "threat_info": {
                "malicious_count": scan_results.get('malicious', 0),
                "suspicious_count": scan_results.get('suspicious', 0),
                "detections": scan_results.get('detections', [])[:10]  # Store top 10
            }
        }
        
        save_quarantine_db(qdb)
        
        # Delete original file
        filepath.unlink()
        
        console.print(f"\n[green]✅ File quarantined successfully![/green]")
        console.print(f"[cyan]Quarantine location: {quarantine_path}[/cyan]")
        console.print(f"[cyan]Original location saved for restoration[/cyan]")
        
        return True, str(quarantine_path)
    
    except Exception as e:
        console.print(f"[red]❌ Quarantine failed: {e}[/red]")
        return False, str(e)

def restore_from_quarantine(quarantine_name):
    """Restore file from quarantine to original location"""
    try:
        qdb = load_quarantine_db()
        
        if quarantine_name not in qdb:
            return False, "File not found in quarantine database"
        
        file_info = qdb[quarantine_name]
        quarantine_path = QUARANTINE_DIR / quarantine_name
        original_path = Path(file_info['original_path'])
        
        if not quarantine_path.exists():
            return False, "Quarantine file not found on disk"
        
        # Check if original location is writable
        if original_path.exists():
            return False, "A file already exists at the original location"
        
        # Read quarantined file and decrypt
        with open(quarantine_path, 'rb') as f:
            encrypted = f.read()
        
        # Decrypt (reverse XOR)
        decrypted = bytes([b ^ 0xAA for b in encrypted])
        
        # Restore to original location
        with open(original_path, 'wb') as f:
            f.write(decrypted)
        
        # Delete from quarantine
        quarantine_path.unlink()
        del qdb[quarantine_name]
        save_quarantine_db(qdb)
        
        console.print(f"[green]✅ File restored to: {original_path}[/green]")
        return True, str(original_path)
    
    except Exception as e:
        return False, str(e)

def delete_from_quarantine(quarantine_name):
    """Permanently delete file from quarantine"""
    try:
        qdb = load_quarantine_db()
        
        if quarantine_name not in qdb:
            return False, "File not found in database"
        
        quarantine_path = QUARANTINE_DIR / quarantine_name
        
        if quarantine_path.exists():
            quarantine_path.unlink()
        
        del qdb[quarantine_name]
        save_quarantine_db(qdb)
        
        console.print(f"[green]✅ File permanently deleted[/green]")
        return True, "Deleted successfully"
    
    except Exception as e:
        return False, str(e)
    
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
# ENHANCED FILE BROWSER (FIXED)
# ============================================================================

def browse_files():
    """Interactive file browser for easy file selection"""
    clear_screen()
    console.print(Panel("[cyan bold]📁 File Browser[/cyan bold]", border_style="cyan"))
    
    console.print("\n[yellow]Select a location:[/yellow]\n")
    
    # Show common paths with better formatting
    paths_list = []
    for i, (name, path) in enumerate(COMMON_PATHS.items(), 1):
        exists = "✓" if path.exists() else "✗"
        color = "green" if path.exists() else "dim"
        console.print(f"  [{color}]{i:2d}. {exists} {name}[/{color}]")
        if path.exists():
            console.print(f"      [dim]{path}[/dim]")
        paths_list.append(path)
    
    console.print(f"\n  [cyan] 0. Enter custom path[/cyan]")
    console.print(f"  [yellow]99. Cancel[/yellow]\n")
    
    choice = input("Select location: ").strip()
    
    if choice == '99':
        return None
    elif choice == '0':
        custom_path = input("\nEnter full path: ").strip().strip('"').strip("'")
        if custom_path:
            selected_path = Path(custom_path)
            if not selected_path.exists():
                console.print(f"[red]❌ Path does not exist: {selected_path}[/red]")
                time.sleep(2)
                return browse_files()
        else:
            return browse_files()
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(paths_list):
                selected_path = paths_list[idx]
            else:
                console.print("[red]Invalid choice[/red]")
                time.sleep(1)
                return browse_files()
        except ValueError:
            console.print("[red]Invalid input[/red]")
            time.sleep(1)
            return browse_files()
    
    if not selected_path.exists():
        console.print(f"[red]❌ Path does not exist: {selected_path}[/red]")
        time.sleep(2)
        return browse_files()
    
    # List files in selected directory
    return browse_directory(selected_path)

def browse_directory(directory):
    """Browse files in a specific directory"""
    clear_screen()
    console.print(Panel(f"[cyan]📂 {directory}[/cyan]", border_style="cyan"))
    
    try:
        items = list(directory.iterdir())
        files = [item for item in items if item.is_file()]
        dirs = [item for item in items if item.is_dir()]
        
        # Sort
        dirs.sort(key=lambda x: x.name.lower())
        files.sort(key=lambda x: x.name.lower())
        
        # Show parent directory option
        console.print("\n[yellow bold]Navigation:[/yellow bold]")
        console.print("  0. 📁 .. (Parent Directory)")
        
        # Show directories
        if dirs:
            console.print("\n[yellow bold]Directories:[/yellow bold]")
            for i, d in enumerate(dirs[:30], 1):
                console.print(f"  {i}. 📁 {d.name}")
        
        # Show files
        if files:
            console.print("\n[yellow bold]Files:[/yellow bold]")
            start_num = len(dirs) + 1
            for i, f in enumerate(files[:50], start_num):
                size = f.stat().st_size
                if size < 1024:
                    size_str = f"{size}B"
                elif size < 1024 * 1024:
                    size_str = f"{size/1024:.1f}KB"
                else:
                    size_str = f"{size/(1024*1024):.2f}MB"
                console.print(f"  {i}. 📄 {f.name} ({size_str})")
        
        if not dirs and not files:
            console.print("\n[dim]  (empty directory)[/dim]")
        
        total_items = len(dirs) + min(len(files), 50)
        if len(files) > 50:
            console.print(f"\n  [dim]... and {len(files)-50} more files[/dim]")
        
        console.print("\n  [cyan]98. Change location[/cyan]")
        console.print("  [yellow]99. Cancel[/yellow]\n")
        
        choice = input("Select item: ").strip()
        
        if choice == '99':
            return None
        elif choice == '98':
            return browse_files()
        elif choice == '0':
            # Go to parent directory
            parent = directory.parent
            if parent != directory:  # Prevent going above root
                return browse_directory(parent)
            else:
                console.print("[yellow]Already at root[/yellow]")
                time.sleep(1)
                return browse_directory(directory)
        else:
            try:
                idx = int(choice)
                
                # Check if it's a directory
                if 1 <= idx <= len(dirs):
                    selected_dir = dirs[idx - 1]
                    return browse_directory(selected_dir)
                
                # Check if it's a file
                elif len(dirs) < idx <= total_items:
                    file_idx = idx - len(dirs) - 1
                    if 0 <= file_idx < len(files):
                        return files[file_idx]
                    else:
                        console.print("[red]Invalid selection[/red]")
                        time.sleep(1)
                        return browse_directory(directory)
                else:
                    console.print("[red]Invalid selection[/red]")
                    time.sleep(1)
                    return browse_directory(directory)
            except ValueError:
                console.print("[red]Invalid input[/red]")
                time.sleep(1)
                return browse_directory(directory)
    
    except PermissionError:
        console.print(f"[red]❌ Permission denied: {directory}[/red]")
        time.sleep(2)
        return browse_files()
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
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
    """Check if domain has MX records"""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        mx_records = resolver.resolve(domain, 'MX')
        mx_list = [str(r.exchange) for r in mx_records]
        return True, f"Found {len(mx_records)} MX record(s)", mx_list
    except ImportError:
        return None, "Install: pkg install python-dnspython", []
    except Exception as e:
        return False, f"MX check error: {str(e)}", []

def check_spf_record(domain):
    """Check for SPF record"""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        txt_records = resolver.resolve(domain, 'TXT')
        for record in txt_records:
            txt_string = str(record)
            if 'v=spf1' in txt_string.lower():
                return True, "SPF record found", txt_string
        return False, "No SPF record", None
    except:
        return False, "Could not check SPF", None

def check_dmarc_record(domain):
    """Check for DMARC record"""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = resolver.resolve(dmarc_domain, 'TXT')
        for record in txt_records:
            txt_string = str(record)
            if 'v=DMARC1' in txt_string:
                return True, "DMARC record found", txt_string
        return False, "No DMARC record", None
    except:
        return False, "No DMARC record", None

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
    
    # Check if dnspython is installed and setup DNS
    try:
        import dns.resolver
        
        # Configure DNS resolver for Termux
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        
        # MX Records
        try:
            mx_records = resolver.resolve(domain, 'MX')
            results['MX'] = [str(r.exchange) for r in mx_records]
            console.print(f"[green bold]MX Records (Mail Servers):[/green bold]")
            for mx in sorted(mx_records, key=lambda x: x.preference):
                console.print(f"  → Priority {mx.preference}: {mx.exchange}")
        except dns.resolver.NoAnswer:
            console.print(f"[yellow]MX Records: Not found[/yellow]")
        except dns.resolver.NXDOMAIN:
            console.print(f"[red]MX Records: Domain does not exist[/red]")
        except Exception as e:
            console.print(f"[yellow]MX Records: {str(e)}[/yellow]")
        
        console.print()
        
        # TXT Records
        try:
            txt_records = resolver.resolve(domain, 'TXT')
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
        except dns.resolver.NXDOMAIN:
            console.print(f"[red]TXT Records: Domain does not exist[/red]")
        except Exception as e:
            console.print(f"[yellow]TXT Records: {str(e)}[/yellow]")
        
        console.print()
        
        # NS Records (Name Servers)
        try:
            ns_records = resolver.resolve(domain, 'NS')
            results['NS'] = [str(r) for r in ns_records]
            console.print(f"[green bold]NS Records (Name Servers):[/green bold]")
            for ns in ns_records:
                console.print(f"  → {ns}")
        except dns.resolver.NoAnswer:
            console.print(f"[yellow]NS Records: Not found[/yellow]")
        except dns.resolver.NXDOMAIN:
            console.print(f"[red]NS Records: Domain does not exist[/red]")
        except Exception as e:
            console.print(f"[yellow]NS Records: {str(e)}[/yellow]")
        
        console.print()
        
        # AAAA Records (IPv6)
        try:
            aaaa_records = resolver.resolve(domain, 'AAAA')
            results['AAAA'] = [str(r) for r in aaaa_records]
            console.print(f"[green bold]AAAA Records (IPv6):[/green bold]")
            for ipv6 in aaaa_records:
                console.print(f"  → {ipv6}")
        except dns.resolver.NoAnswer:
            console.print(f"[yellow]AAAA Records: Not found (IPv6 not configured)[/yellow]")
        except dns.resolver.NXDOMAIN:
            console.print(f"[red]AAAA Records: Domain does not exist[/red]")
        except Exception as e:
            console.print(f"[yellow]AAAA Records: {str(e)}[/yellow]")
        
        console.print()
        
        # CNAME Records
        try:
            cname_records = resolver.resolve(domain, 'CNAME')
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
    
    # Email-specific checks
    if input_type == "email":
        # MX Records
        mx_ok, mx_msg, mx_list = check_mx_records(domain)
        results['mx'] = mx_ok
        if mx_ok:
            table.add_row("MX Records", f"[green]✓ {mx_msg}[/green]")
        elif mx_ok is None:
            table.add_row("MX Records", f"[yellow]⚠️ {mx_msg}[/yellow]")
        else:
            table.add_row("MX Records", f"[red]✗ {mx_msg}[/red]")
        
        # SPF Record
        spf_ok, spf_msg, _ = check_spf_record(domain)
        table.add_row(
            "SPF Record",
            f"[green]✓ {spf_msg}[/green]" if spf_ok else f"[yellow]⚠️ {spf_msg}[/yellow]"
        )
        
        # DMARC Record
        dmarc_ok, dmarc_msg, _ = check_dmarc_record(domain)
        table.add_row(
            "DMARC Record",
            f"[green]✓ {dmarc_msg}[/green]" if dmarc_ok else f"[yellow]⚠️ {dmarc_msg}[/yellow]"
        )
        
        # Disposable Email
        is_disp, disp_msg = check_disposable_email(domain)
        results['disposable'] = is_disp
        table.add_row(
            "Disposable Email",
            f"[red]⚠️ {disp_msg}[/red]" if is_disp else f"[green]✓ {disp_msg}[/green]"
        )
    
    # Domain Age
    age_info = check_domain_age(domain)
    results['age'] = age_info
    if age_info.get('found'):
        years = age_info['age_years']
        if years >= 5:
            color = "green"
            status = "✓"
        elif years >= 1:
            color = "yellow"
            status = "⚠️"
        else:
            color = "red"
            status = "⚠️"
        table.add_row("Domain Age", f"[{color}]{status} {age_info['registered']} ({years} years old)[/{color}]")
    else:
        table.add_row("Domain Age", "[yellow]⚠️ Could not determine[/yellow]")
    
    # Heuristics
    risk_score, warnings = analyze_domain_heuristics(domain)
    results['heuristic'] = risk_score
    results['warnings'] = warnings
    if risk_score >= 50:
        color = "red"
        status = "⚠️"
    elif risk_score >= 25:
        color = "yellow"
        status = "⚠️"
    else:
        color = "green"
        status = "✓"
    table.add_row("Heuristic Analysis", f"[{color}]{status} Risk Score: {risk_score}/100[/{color}]")
    
    # VirusTotal
    vt_status, vt_msg, vt_data = check_virustotal_reputation(domain)
    results['virustotal'] = vt_data
    
    # Parse VT status for display
    if vt_data:
        mal = vt_data.get('malicious', 0)
        sus = vt_data.get('suspicious', 0)
        if mal > 0:
            vt_display = f"[red]⚠️ {vt_msg}[/red]"
        elif sus > 0:
            vt_display = f"[yellow]⚠️ {vt_msg}[/yellow]"
        else:
            vt_display = f"[green]✓ {vt_msg}[/green]"
    else:
        vt_display = f"[yellow]⚠️ {vt_msg}[/yellow]"
    
    table.add_row("VirusTotal", vt_display)
    
    console.print(table)
    
    # Show warnings
    if warnings:
        console.print(f"\n[yellow bold]⚠️ Security Warnings:[/yellow bold]")
        for w in warnings:
            console.print(f"  • {w}")
    
    # Calculate final risk score
    overall_risk = calculate_risk_score(results)
    
    # Final verdict - FIXED LOGIC
    console.print()
    if overall_risk >= 70:
        verdict = "[red bold]🚨 HIGH RISK - DO NOT TRUST[/red bold]"
        advice = "Multiple serious security concerns detected. Avoid this domain."
        border_color = "red"
    elif overall_risk >= 50:
        verdict = "[yellow bold]⚠️ SUSPICIOUS - EXERCISE CAUTION[/yellow bold]"
        advice = "Several red flags detected. Verify legitimacy before proceeding."
        border_color = "yellow"
    elif overall_risk >= 30:
        verdict = "[yellow]⚠️ MODERATE RISK - BE CAREFUL[/yellow]"
        advice = "Some concerns detected. Use extra caution."
        border_color = "yellow"
    else:
        verdict = "[green bold]✅ APPEARS SAFE[/green bold]"
        advice = "No significant threats detected."
        border_color = "green"
    
    console.print(Panel.fit(
        f"{verdict}\n\n"
        f"Overall Risk Score: {overall_risk}/100\n"
        f"{advice}",
        title="[bold]Final Assessment[/bold]",
        border_style=border_color
    ))
    
    # Export
    console.print()
    if input("Export report? (y/N): ").lower() == 'y':
        export_json_report(user_input, domain, input_type, results, overall_risk, warnings)
    
    save_to_history("Domain Checker", {"domain": domain, "risk": overall_risk})
    press_enter()

# ============================================================================
# ENHANCED FILE SCANNER WITH QUARANTINE
# ============================================================================

def file_scanner_tool():
    """Enhanced File Scanner with quarantine functionality"""
    clear_screen()
    console.print(Panel("[cyan bold]🦠 File Scanner (VirusTotal)[/cyan bold]", border_style="cyan"))
    
    vt_key = get_vt_api_key()
    if not vt_key:
        console.print("\n[red bold]❌ VirusTotal API key required![/red bold]")
        console.print("[yellow]Get free key: https://www.virustotal.com/gui/my-apikey[/yellow]")
        console.print(f"[yellow]Save to: {BASE_DIR}/.env[/yellow]")
        console.print(f"[yellow]Format: VT_API_KEY=your_key_here[/yellow]")
        press_enter()
        return
    
    console.print("\n[yellow bold]Choose input method:[/yellow bold]")
    console.print("  1. Browse files (recommended)")
    console.print("  2. Enter file path manually")
    console.print("  3. Cancel\n")
    
    choice = input("Choice (1-3): ").strip()
    
    filepath = None
    
    if choice == '1':
        filepath = browse_files()
        if not filepath:
            console.print("[yellow]No file selected[/yellow]")
            press_enter()
            return
    elif choice == '2':
        filepath_input = input("\n📂 Enter full file path: ").strip()
        # Remove quotes if present
        filepath_input = filepath_input.strip('"').strip("'")
        
        if not filepath_input:
            console.print("[red]❌ No path provided[/red]")
            press_enter()
            return
        
        filepath = Path(filepath_input)
        
        if not filepath.exists():
            console.print(f"[red]❌ File not found: {filepath}[/red]")
            console.print(f"[yellow]Tip: Use option 1 (Browse files) for easier navigation[/yellow]")
            press_enter()
            return
        
        if not filepath.is_file():
            console.print(f"[red]❌ Path is a directory, not a file: {filepath}[/red]")
            press_enter()
            return
    elif choice == '3':
        return
    else:
        console.print("[red]Invalid choice[/red]")
        press_enter()
        return
    
    # Verify file exists and is a file
    if not filepath or not filepath.exists():
        console.print(f"[red]❌ File not found[/red]")
        press_enter()
        return
    
    if not filepath.is_file():
        console.print(f"[red]❌ Path is not a file[/red]")
        press_enter()
        return
    
    # Display file info
    file_size = filepath.stat().st_size
    file_size_mb = file_size / (1024 * 1024)
    
    console.print(f"\n[cyan bold]📁 File Information:[/cyan bold]")
    console.print(f"  Name: {filepath.name}")
    console.print(f"  Size: {file_size_mb:.2f}MB ({file_size:,} bytes)")
    console.print(f"  Path: {filepath}")
    console.print()
    
    # Check file size limit
    if file_size_mb > 650:
        console.print(f"[red]❌ File too large ({file_size_mb:.2f}MB)[/red]")
        console.print(f"[yellow]VirusTotal limit: 650MB[/yellow]")
        press_enter()
        return
    
    if file_size_mb > 32:
        console.print(f"[yellow]⚠️ File size ({file_size_mb:.2f}MB) exceeds free API limit (32MB)[/yellow]")
        console.print(f"[yellow]Will check hash only. Upload requires Premium API.[/yellow]\n")
    
    # Calculate file hash
    console.print("[cyan]🔍 Calculating file hash...[/cyan]")
    sha256 = hashlib.sha256()
    
    try:
        with open(filepath, 'rb') as f:
            if file_size_mb > 10:  # Show progress for files > 10MB
                with Progress(
                    SpinnerColumn(),
                    TextColumn(f"[cyan]Hashing {file_size_mb:.1f}MB..."),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task("", total=file_size)
                    bytes_read = 0
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        sha256.update(chunk)
                        bytes_read += len(chunk)
                        progress.update(task, completed=bytes_read)
            else:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256.update(chunk)
        
        file_hash = sha256.hexdigest()
        console.print(f"[green]✅ SHA-256: {file_hash}[/green]\n")
    
    except Exception as e:
        console.print(f"[red]❌ Hash calculation failed: {e}[/red]")
        press_enter()
        return
    
    # Check VirusTotal database
    console.print("[cyan]🔍 Checking VirusTotal database...[/cyan]")
    vt_data = get_virustotal_file_report(file_hash)
    
    if not vt_data:
        console.print("[yellow]⚠️ File not in VirusTotal database[/yellow]")
        console.print("[yellow]   This file has never been scanned before[/yellow]\n")
        
        if file_size_mb > 32:
            console.print(f"[red]❌ Cannot upload: File exceeds 32MB free API limit[/red]")
            console.print(f"[yellow]💡 Options:[/yellow]")
            console.print(f"[yellow]   1. Upload manually: https://www.virustotal.com/gui/home/upload[/yellow]")
            console.print(f"[yellow]   2. Use local antivirus software[/yellow]")
            press_enter()
            return
        
        upload_choice = input("📤 Upload file for scanning? (y/N): ").strip().lower()
        
        if upload_choice != 'y':
            console.print("[yellow]Scan cancelled[/yellow]")
            press_enter()
            return
        
        console.print("\n[cyan]📤 Uploading file to VirusTotal...[/cyan]")
        analysis_id, msg = upload_file_to_virustotal(str(filepath))
        
        if not analysis_id:
            console.print(f"[red]❌ Upload failed: {msg}[/red]")
            press_enter()
            return
        
        console.print(f"[green]✅ Upload successful![/green]")
        console.print(f"[cyan]Analysis ID: {analysis_id}[/cyan]\n")
        
        # Wait for analysis
        vt_data = wait_for_analysis(analysis_id)
    else:
        console.print("[green]✅ File found in VirusTotal database![/green]")
        console.print("[cyan]   Using existing scan results[/cyan]\n")
    
    if not vt_data:
        console.print("[red]❌ Failed to get scan results[/red]")
        press_enter()
        return
    
    # Parse scan results
    parsed = parse_vt_file_results(vt_data)
    
    if not parsed:
        console.print("[red]❌ Could not parse scan results[/red]")
        press_enter()
        return
    
    stats = parsed['stats']
    detections = parsed['detections']
    file_info = parsed['file_info']
    
    # Display results
    console.print(Panel.fit(
        f"[bold]Scan Results[/bold]\n\n"
        f"[red]Malicious: {stats['malicious']}[/red] | "
        f"[yellow]Suspicious: {stats['suspicious']}[/yellow] | "
        f"[green]Clean: {stats['harmless']}[/green]\n"
        f"Total Engines: {stats['total']}",
        border_style="cyan"
    ))
    
    # Verdict
    console.print()
    threat_detected = False
    
    if stats['malicious'] > 0:
        console.print(Panel.fit(
            f"[red bold]🚨 THREAT DETECTED[/red bold]\n\n"
            f"{stats['malicious']} security vendor(s) flagged this file as MALICIOUS!\n"
            f"[red bold]⚠️ DO NOT EXECUTE THIS FILE[/red bold]",
            border_style="red"
        ))
        threat_detected = True
    elif stats['suspicious'] > 0:
        console.print(Panel.fit(
            f"[yellow bold]⚠️ SUSPICIOUS FILE[/yellow bold]\n\n"
            f"{stats['suspicious']} vendor(s) flagged this file as suspicious.\n"
            f"Exercise extreme caution before executing.",
            border_style="yellow"
        ))
        threat_detected = True
    else:
        console.print(Panel.fit(
            f"[green bold]✅ FILE APPEARS CLEAN[/green bold]\n\n"
            f"No threats detected by {stats['total']} security vendors.\n"
            f"File appears safe, but always exercise caution.",
            border_style="green"
        ))
    
    # Show detections if any
    if detections:
        console.print(f"\n[red bold]⚠️ Threat Detections ({len(detections)} vendors):[/red bold]")
        
        detection_table = Table(border_style="red", show_header=True, header_style="bold red")
        detection_table.add_column("#", style="cyan", width=4)
        detection_table.add_column("Vendor", style="yellow", width=25)
        detection_table.add_column("Category", style="red", width=12)
        detection_table.add_column("Detection Name", style="white", width=35)
        
        for i, det in enumerate(detections[:15], 1):
            category_color = "red" if det['category'] == "malicious" else "yellow"
            detection_table.add_row(
                str(i),
                det['vendor'],
                f"[{category_color}]{det['category'].upper()}[/{category_color}]",
                det['result'][:33]
            )
        
        console.print(detection_table)
        
        if len(detections) > 15:
            console.print(f"\n[yellow]+ {len(detections)-15} more detections[/yellow]")
    
    # Offer detailed vendor assessment
    if vt_data:
        show_detail = input("\n📋 Show detailed vendor assessment? (y/N): ").strip().lower()
        if show_detail == 'y':
            display_detailed_vt_assessment(vt_data)
    
    # File information
    console.print(f"\n[cyan bold]📋 File Technical Details:[/cyan bold]")
    console.print(f"  SHA-256: {file_info['sha256']}")
    console.print(f"  File Type: {file_info['type']}")
    console.print(f"  Size: {file_info['size']:,} bytes")
    
    # Quarantine option if threat detected
    if threat_detected:
        console.print(f"\n[red bold]🔒 QUARANTINE OPTIONS:[/red bold]")
        console.print("[yellow]This file has been flagged as a potential threat.[/yellow]")
        
        quarantine_choice = input("\n🗂️  Move file to quarantine? (Y/n): ").strip().lower()
        
        if quarantine_choice != 'n':
            scan_results = {
                'hash': file_hash,
                'malicious': stats['malicious'],
                'suspicious': stats['suspicious'],
                'detections': detections
            }
            
            success, result = quarantine_file(filepath, scan_results)
            
            if success:
                console.print(f"\n[green bold]✅ File successfully quarantined![/green bold]")
                console.print(f"[cyan]You can manage quarantined files from the main menu.[/cyan]")
            else:
                console.print(f"\n[red]❌ Quarantine failed: {result}[/red]")
                console.print(f"[yellow]⚠️ Please manually delete this file: {filepath}[/yellow]")
    
    # Save to history
    save_to_history("File Scanner", {
        "file": filepath.name,
        "path": str(filepath),
        "size_mb": round(file_size_mb, 2),
        "hash": file_hash,
        "malicious": stats['malicious'],
        "suspicious": stats['suspicious'],
        "clean": stats['harmless'],
        "threat_detected": threat_detected,
        "quarantined": threat_detected and quarantine_choice != 'n'
    })
    
    press_enter()

# ============================================================================
# QUARANTINE MANAGER
# ============================================================================

def manage_quarantine():
    """Manage quarantined files"""
    while True:
        clear_screen()
        console.print(Panel("[cyan bold]🗂️  Quarantine Manager[/cyan bold]", border_style="cyan"))
        
        qdb = load_quarantine_db()
        
        if not qdb:
            console.print("\n[green]✅ No files in quarantine[/green]")
            console.print("[dim]All clear! No threats detected.[/dim]")
            press_enter()
            return
        
        # Display quarantined files
        console.print(f"\n[yellow bold]Quarantined Files: {len(qdb)}[/yellow bold]\n")
        
        table = Table(border_style="yellow", show_header=True, header_style="bold yellow")
        table.add_column("#", style="cyan", width=3)
        table.add_column("Original Name", style="white", width=25)
        table.add_column("Size", style="cyan", width=10)
        table.add_column("Threats", style="red", width=8)
        table.add_column("Date", style="dim", width=18)
        
        q_items = list(qdb.items())
        for i, (qname, qinfo) in enumerate(q_items, 1):
            size_mb = qinfo['file_size'] / (1024 * 1024)
            size_str = f"{size_mb:.2f}MB" if size_mb >= 1 else f"{qinfo['file_size']/1024:.1f}KB"
            threat_count = qinfo['threat_info']['malicious_count']
            q_date = datetime.fromisoformat(qinfo['quarantine_date']).strftime('%Y-%m-%d %H:%M')
            
            table.add_row(
                str(i),
                qinfo['original_name'][:23],
                size_str,
                str(threat_count),
                q_date
            )
        
        console.print(table)
        
        console.print(f"\n[cyan bold]Options:[/cyan bold]")
        console.print("  1. View file details")
        console.print("  2. Restore file (use with caution!)")
        console.print("  3. Delete permanently")
        console.print("  4. Delete all quarantined files")
        console.print("  5. Back to main menu\n")
        
        choice = input("Select option (1-5): ").strip()
        
        if choice == '1':
            # View details
            file_num = input("\nEnter file number: ").strip()
            try:
                idx = int(file_num) - 1
                if 0 <= idx < len(q_items):
                    qname, qinfo = q_items[idx]
                    
                    console.print(f"\n[cyan bold]File Details:[/cyan bold]")
                    console.print(f"  Original Name: {qinfo['original_name']}")
                    console.print(f"  Original Path: {qinfo['original_path']}")
                    console.print(f"  File Size: {qinfo['file_size']:,} bytes")
                    console.print(f"  SHA-256: {qinfo['sha256']}")
                    console.print(f"  Quarantined: {qinfo['quarantine_date']}")
                    console.print(f"\n[red bold]Threat Information:[/red bold]")
                    console.print(f"  Malicious Detections: {qinfo['threat_info']['malicious_count']}")
                    console.print(f"  Suspicious Detections: {qinfo['threat_info']['suspicious_count']}")
                    
                    if qinfo['threat_info']['detections']:
                        console.print(f"\n  Top Detections:")
                        for det in qinfo['threat_info']['detections'][:5]:
                            console.print(f"    • {det['vendor']}: {det['result']}")
                    
                    press_enter()
                else:
                    console.print("[red]Invalid file number[/red]")
                    time.sleep(1)
            except ValueError:
                console.print("[red]Invalid input[/red]")
                time.sleep(1)
        
        elif choice == '2':
            # Restore file
            file_num = input("\nEnter file number to restore: ").strip()
            try:
                idx = int(file_num) - 1
                if 0 <= idx < len(q_items):
                    qname, qinfo = q_items[idx]
                    
                    console.print(f"\n[yellow bold]⚠️ WARNING:[/yellow bold]")
                    console.print(f"[yellow]This file was quarantined as a threat![/yellow]")
                    console.print(f"[yellow]Restoring may put your device at risk.[/yellow]")
                    console.print(f"\nFile: {qinfo['original_name']}")
                    console.print(f"Threats: {qinfo['threat_info']['malicious_count']} malicious detections")
                    
                    confirm = input("\nAre you SURE you want to restore? (type 'RESTORE' to confirm): ").strip()
                    
                    if confirm == 'RESTORE':
                        success, msg = restore_from_quarantine(qname)
                        if success:
                            console.print(f"[green]✅ File restored to: {qinfo['original_path']}[/green]")
                        else:
                            console.print(f"[red]❌ Failed to restore: {msg}[/red]")
                            time.sleep(2)
                    else:
                        console.print("[yellow]Restore cancelled[/yellow]")
                        time.sleep(1)
            except ValueError:
                console.print("[red]Invalid input[/red]")
                time.sleep(1)

        elif choice == '3':
            # Delete permanently
            file_num = input("\nEnter file number to delete: ").strip()
            try:
                idx = int(file_num) - 1
                if 0 <= idx < len(q_items):
                    qname, qinfo = q_items[idx]
                    
                    console.print(f"\nFile: {qinfo['original_name']}")
                    confirm = input("Delete permanently? (y/N): ").strip().lower()
                    
                    if confirm == 'y':
                        success, msg = delete_from_quarantine(qname)
                        if success:
                            console.print(f"[green]✅ File deleted permanently[/green]")
                        else:
                            console.print(f"[red]❌ Delete failed: {msg}[/red]")
                        time.sleep(2)
                    else:
                        console.print("[yellow]Cancelled[/yellow]")
                        time.sleep(1)
                else:
                    console.print("[red]Invalid file number[/red]")
                    time.sleep(1)
            except ValueError:
                console.print("[red]Invalid input[/red]")
                time.sleep(1)
    
        elif choice == '4':
            # Delete all
            console.print(f"\n[red bold]⚠️ WARNING:[/red bold]")
            console.print(f"[red]This will permanently delete all {len(qdb)} quarantined files![/red]")
            confirm = input("\nType 'DELETE ALL' to confirm: ").strip()
            
            if confirm == 'DELETE ALL':
                deleted_count = 0
                for qname in list(qdb.keys()):
                    success, _ = delete_from_quarantine(qname)
                    if success:
                        deleted_count += 1
                
                console.print(f"[green]✅ Deleted {deleted_count} file(s)[/green]")
                time.sleep(2)
            else:
                console.print("[yellow]Cancelled[/yellow]")
                time.sleep(1)
        
        elif choice == '5':
            break
        else:
            console.print("[red]Invalid choice[/red]")
            time.sleep(1)

# ============================================================================
# VIRUSTOTAL DETAILED VENDOR ASSESSMENT
# ============================================================================

def display_detailed_vt_assessment(vt_data):
    """Display detailed VirusTotal vendor assessment like the report"""
    if not vt_data:
        return
    
    try:
        attrs = vt_data.get("data", {}).get("attributes", {})
        results = attrs.get("last_analysis_results", {})
        
        if not results:
            return
        
        # Categorize vendors
        malicious_vendors = []
        suspicious_vendors = []
        harmless_vendors = []
        undetected_vendors = []
        
        for vendor, result in results.items():
            category = result.get("category", "undetected")
            vendor_result = result.get("result", "clean")
            
            if category == "malicious":
                malicious_vendors.append((vendor, vendor_result))
            elif category == "suspicious":
                suspicious_vendors.append((vendor, vendor_result))
            elif category == "harmless" or category == "clean":
                harmless_vendors.append((vendor, vendor_result))
            else:  # undetected, timeout, etc.
                undetected_vendors.append((vendor, category))
        
        console.print("\n" + "="*70)
        console.print("[cyan bold]DETAILED VIRUSTOTAL VENDOR ASSESSMENT[/cyan bold]")
        console.print("="*70 + "\n")
        
        # MALICIOUS Detections
        if malicious_vendors:
            console.print(f"[red bold]⚠️  MALICIOUS Detections ({len(malicious_vendors)}):[/red bold]")
            for vendor, detection in sorted(malicious_vendors):
                console.print(f"  [red]•[/red] {vendor}: [yellow]{detection}[/yellow]")
            console.print()
        
        # SUSPICIOUS Detections
        if suspicious_vendors:
            console.print(f"[yellow bold]⚠️  SUSPICIOUS Detections ({len(suspicious_vendors)}):[/yellow bold]")
            for vendor, detection in sorted(suspicious_vendors):
                console.print(f"  [yellow]•[/yellow] {vendor}: [yellow]{detection}[/yellow]")
            console.print()
        
        # HARMLESS/CLEAN Detections
        if harmless_vendors:
            console.print(f"[green bold]✓ HARMLESS/CLEAN ({len(harmless_vendors)}):[/green bold]")
            # Show in columns for space efficiency
            vendors_per_line = 3
            for i in range(0, len(harmless_vendors), vendors_per_line):
                batch = harmless_vendors[i:i+vendors_per_line]
                line_items = []
                for vendor, _ in batch:
                    line_items.append(f"{vendor}: clean")
                console.print(f"  [green]•[/green] " + " | ".join(line_items))
            console.print()
        
        # UNDETECTED/NO RESULT
        if undetected_vendors:
            console.print(f"[dim]UNDETECTED/NO RESULT ({len(undetected_vendors)}):[/dim]")
            # Show in columns
            vendors_per_line = 3
            for i in range(0, len(undetected_vendors), vendors_per_line):
                batch = undetected_vendors[i:i+vendors_per_line]
                line_items = []
                for vendor, status in batch:
                    line_items.append(f"{vendor}: {status}")
                console.print(f"  [dim]•[/dim] " + " | ".join(line_items))
            console.print()
        
        # Summary
        total = len(malicious_vendors) + len(suspicious_vendors) + len(harmless_vendors) + len(undetected_vendors)
        threats = len(malicious_vendors) + len(suspicious_vendors)
        clean = len(harmless_vendors) + len(undetected_vendors)
        
        console.print("="*70)
        console.print(f"[cyan bold]SCAN SUMMARY:[/cyan bold]")
        console.print(f"  • [red]{len(malicious_vendors)} engine(s) flagged as MALICIOUS[/red]")
        if suspicious_vendors:
            console.print(f"  • [yellow]{len(suspicious_vendors)} engine(s) flagged as SUSPICIOUS[/yellow]")
        console.print(f"  • [green]{len(harmless_vendors)} engine(s) rated as HARMLESS[/green]")
        console.print(f"  • [dim]{len(undetected_vendors)} engine(s) found NO THREATS[/dim]")
        console.print(f"  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        console.print(f"  Total Scanned: {total} engines")
        
        if threats > 0:
            threat_pct = (threats / total * 100) if total > 0 else 0
            clean_pct = (clean / total * 100) if total > 0 else 0
            console.print(f"  [red]Threats: {threats} ({threat_pct:.1f}%)[/red] | [green]Clean: {clean} ({clean_pct:.1f}%)[/green]")
        else:
            console.print(f"  [green bold]✓ All {total} engines reported clean (100%)[/green bold]")
        
        console.print("="*70 + "\n")
        
        # VirusTotal link
        file_id = attrs.get("sha256")
        if file_id:
            import base64
            # Create VT URL
            vt_url = f"https://www.virustotal.com/gui/file/{file_id}/detection"
            console.print(f"[cyan]📊 Full VirusTotal Report: {vt_url}[/cyan]\n")
    
    except Exception as e:
        console.print(f"[yellow]Could not display detailed assessment: {e}[/yellow]")
        
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
    
    # Check quarantine status
    qdb = load_quarantine_db()
    if qdb:
        console.print(f"\n[yellow]⚠️  {len(qdb)} file(s) in quarantine[/yellow]\n")
    else:
        console.print()
    
    console.print("[cyan]1.[/cyan] DNS Lookup")
    console.print("[cyan]2.[/cyan] Ping Tool")
    console.print("[cyan]3.[/cyan] Email & Domain Trust Checker")
    console.print("[cyan]4.[/cyan] File Scanner (VirusTotal)")
    console.print("[cyan]5.[/cyan] View History")
    console.print("[cyan]6.[/cyan] Manage Quarantine")
    console.print("[cyan]7.[/cyan] Clear Cache")
    console.print("[cyan]8.[/cyan] Exit\n")
    
    return input("Choice (1-8): ").strip()

def main():
    # Setup DNS for Termux
    setup_termux_dns()
    
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
            elif choice == '6': manage_quarantine()
            elif choice == '7': clear_cache_tool()
            elif choice == '8':
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