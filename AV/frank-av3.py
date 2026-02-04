#!/usr/bin/env python3
"""
Frankenstein AV v9.0 - Termux Edition
Advanced Antivirus Suite for Android/Termux
Features: Hash Detection, YARA Signatures, Real-time Monitoring, Web Dashboard
Author: Enhanced by AI Assistant
License: Educational Use Only
"""

import hashlib
import os
import requests
import json
import time
from datetime import datetime
import pickle
import subprocess
import argparse
import base64
import urllib.parse
import platform
import sys
from pathlib import Path
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import sqlite3
import re
import threading
from functools import wraps
import shutil
import webbrowser
import socket
from typing import Optional, Tuple, Dict, List

# Optional imports with fallbacks
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("Warning: watchdog not installed. Real-time monitoring unavailable.")

try:
    from flask import Flask, render_template_string, jsonify, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("Warning: flask not installed. Web dashboard unavailable.")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("Warning: yara-python not installed. YARA detection unavailable.")

# Load environment variables from .env file manually (no python-dotenv needed)
def load_env():
    """Load .env file manually."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip().strip('"').strip("'")

load_env()

# ============================================================================
# CONFIGURATION
# ============================================================================

# Detect if running in Termux
IS_TERMUX = os.path.exists('/data/data/com.termux')

# Auto-detect script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# If user wants specific paths, use them; otherwise use script directory
CUSTOM_PATH_1 = "/storage/6BF7-FF88/Android/data/com.termux/files/termux_distro/AV"
CUSTOM_PATH_2 = "/data/data/com.termux/files/AV"
CUSTOM_PATH_3 = "~/storage/external-1/termux_distro/AV"

# Check if custom paths exist and are writable
if os.path.exists(CUSTOM_PATH_1) and os.access(CUSTOM_PATH_1, os.W_OK):
    SCRIPT_DIR = CUSTOM_PATH_1
elif os.path.exists(CUSTOM_PATH_2) and os.access(CUSTOM_PATH_2, os.W_OK):
    SCRIPT_DIR = CUSTOM_PATH_2
elif os.path.exists(CUSTOM_PATH_3) and os.access(CUSTOM_PATH_3, os.W_OK):
    SCRIPT_DIR = CUSTOM_PATH_3
    
# API Keys
MALSHARE_API_KEY = os.getenv("Malshare_API_Key")
HYBRID_API_KEY = os.getenv("Hybrid_API_Key")
VT_API_KEY = os.getenv("VT_API_KEY")

# Built-in malware hashes
LOCAL_MALWARE_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty File Hash",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2a0213efb6ccf15b6d36ea": "EICAR Test File (SHA256)",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test File (MD5)",
}

# Paths
FIM_DB_FILE = os.path.join(SCRIPT_DIR, "fim_database", "termux_fim_db.pkl")
QUARANTINE_DIR = os.path.join(SCRIPT_DIR, "quarantine")
LOG_FILE = os.path.join(SCRIPT_DIR, "logs", "termux_av.log")
REPORTS_DIR = os.path.join(SCRIPT_DIR, "reports")
HASH_DB_FILE = os.path.join(SCRIPT_DIR, "database", "malware_hashes.json")
CUSTOM_HASH_FILE = os.path.join(SCRIPT_DIR, "database", "custom_hashes.json")
THREAT_INTEL_FILE = os.path.join(SCRIPT_DIR, "database", "threat_intel.json")
UPDATE_CONFIG_FILE = os.path.join(SCRIPT_DIR, "config", "update_config.json")
DB_PATH = os.path.join(SCRIPT_DIR, "malware_hashes.db")
RESUME_FILE = os.path.join(SCRIPT_DIR, "vt_resume.json")
YARA_RULES_DIR = os.path.join(SCRIPT_DIR, "yara_rules")
YARA_COMPILED = os.path.join(SCRIPT_DIR, "yara_rules", "compiled_rules.yar")
REALTIME_LOG = os.path.join(SCRIPT_DIR, "logs", "realtime_monitor.log")
DEFAULT_THREAT_FEED_URL = "https://rules.emergingthreats.net/fwrules/emerging-block-ips.txt"

# Threat Intelligence Sources
MALWARE_HASH_SOURCES = {
    "malwarebazaar": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_recent/",
}

THREAT_INTEL_SOURCES = {
    "abuseipdb": "https://api.abuseipdb.com/api/v2/blacklist",
    "blocklist": "https://lists.blocklist.de/lists/all.txt"
}

# API Rate Limiting
VT_RATE_LIMIT = 4  # requests per minute for free tier
VT_LAST_REQUEST = 0
VT_LOCK = threading.Lock()

# Real-time monitoring state
REALTIME_THREATS = []
REALTIME_STATS = {
    'files_scanned': 0,
    'threats_found': 0,
    'started_at': None,
    'monitoring': False
}

# Flask app for web dashboard
if FLASK_AVAILABLE:
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.urandom(24)

# Check if device is rooted
def is_rooted():
    """Check if Android device is rooted."""
    root_paths = ['/system/xbin/su', '/system/bin/su', '/sbin/su', '/system/su', '/su/bin/su']
    for path in root_paths:
        if os.path.exists(path):
            return True
    try:
        result = subprocess.run(['which', 'su'], capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

IS_ROOTED = is_rooted()

# ============================================================================
# COLOR CODES
# ============================================================================

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ============================================================================
# UTILITY DECORATORS
# ============================================================================

def retry_on_failure(retries=3, delay=2):
    """Decorator to retry functions on failure."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == retries - 1:
                        raise
                    log_event(f"Retry {attempt + 1}/{retries} for {func.__name__}: {e}", "WARNING")
                    time.sleep(delay)
            return None
        return wrapper
    return decorator

def rate_limit_vt():
    """Rate limit VirusTotal API calls."""
    global VT_LAST_REQUEST
    with VT_LOCK:
        current_time = time.time()
        time_since_last = current_time - VT_LAST_REQUEST
        min_interval = 60.0 / VT_RATE_LIMIT
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            time.sleep(sleep_time)
        VT_LAST_REQUEST = time.time()

# ============================================================================
# DIRECTORY SETUP
# ============================================================================

def setup_directories():
    """Creates all necessary directories."""
    directories = [
        QUARANTINE_DIR,
        os.path.dirname(LOG_FILE),
        os.path.dirname(FIM_DB_FILE),
        REPORTS_DIR,
        os.path.dirname(HASH_DB_FILE),
        os.path.dirname(UPDATE_CONFIG_FILE),
        YARA_RULES_DIR if YARA_AVAILABLE else None
    ]
    for directory in directories:
        if directory and not os.path.exists(directory):
            try:
                os.makedirs(directory, exist_ok=True)
            except OSError as e:
                print(f"{Colors.FAIL}⚠️  Error creating directory {directory}: {e}{Colors.ENDC}")

# ============================================================================
# LOGGING
# ============================================================================

def log_event(message: str, level: str = "INFO"):
    """Logs events to file with timestamp."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] [{level}] {message}\n"
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except IOError as e:
        print(f"{Colors.FAIL}⚠️  Error writing to log: {e}{Colors.ENDC}")

# ============================================================================
# INPUT VALIDATION
# ============================================================================

def sanitize_path(filepath: str) -> Optional[str]:
    """Sanitize and validate file paths."""
    try:
        abs_path = os.path.abspath(filepath)
        if not os.path.exists(abs_path):
            return None
        return abs_path
    except Exception as e:
        log_event(f"Path sanitization error: {e}", "ERROR")
        return None

def validate_hash(hash_str: str) -> bool:
    """Validate hash format (MD5 or SHA256)."""
    if not hash_str:
        return False
    hash_str = hash_str.strip().lower()
    return bool(re.fullmatch(r'[a-f0-9]{32}|[a-f0-9]{64}', hash_str))

def validate_ip(ip: str) -> bool:
    """Validate IPv4 address."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    try:
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    except:
        return False

def validate_url(url: str) -> bool:
    """Basic URL validation."""
    pattern = r'^https?://.+'
    return bool(re.match(pattern, url))

# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

def init_database():
    """Initialize SQLite database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hashes (
                hash TEXT PRIMARY KEY,
                name TEXT,
                source TEXT,
                date_added TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hash ON hashes(hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_source ON hashes(source)")
        conn.commit()
        conn.close()
        print(f"{Colors.OKGREEN}✅ SQLite DB initialized: {DB_PATH}{Colors.ENDC}")
        log_event("SQLite database initialized", "INFO")
        return True
    except Exception as e:
        print(f"{Colors.FAIL}❌ Database init failed: {e}{Colors.ENDC}")
        log_event(f"Database init error: {e}", "ERROR")
        return False

def get_db_connection() -> Optional[sqlite3.Connection]:
    """Get database connection with error handling."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        log_event(f"Database connection error: {e}", "ERROR")
        return None

def db_add_hash(hash_value: str, name: str = "Unknown", source: str = "Manual") -> bool:
    """Add hash to database."""
    if not validate_hash(hash_value):
        return False
    
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO hashes(hash, name, source, date_added) VALUES (?, ?, ?, ?)",
            (hash_value.lower(), name, source, datetime.now().isoformat())
        )
        conn.commit()
        return True
    except Exception as e:
        log_event(f"DB insert error: {e}", "ERROR")
        return False
    finally:
        conn.close()

def db_check_hash(hash_value: str) -> Optional[Tuple[str, str, str]]:
    """Check if hash exists in database."""
    if not validate_hash(hash_value):
        return None
    
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name, source, date_added FROM hashes WHERE hash = ?",
            (hash_value.lower(),)
        )
        result = cursor.fetchone()
        return tuple(result) if result else None
    except Exception as e:
        log_event(f"DB lookup error: {e}", "ERROR")
        return None
    finally:
        conn.close()

def db_delete_hash(hash_value: str) -> int:
    """Delete hash from database."""
    conn = get_db_connection()
    if not conn:
        return 0
    
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM hashes WHERE hash = ?", (hash_value.lower(),))
        conn.commit()
        deleted = cursor.rowcount
        return deleted
    except Exception as e:
        log_event(f"DB delete error: {e}", "ERROR")
        return 0
    finally:
        conn.close()

# ============================================================================
# FILE OPERATIONS
# ============================================================================

def calculate_file_hash(filepath: str, hash_algo: str = 'sha256') -> Optional[str]:
    """Calculate file hash."""
    sanitized = sanitize_path(filepath)
    if not sanitized or not os.path.isfile(sanitized):
        return None
    
    try:
        hasher = hashlib.sha256() if hash_algo == 'sha256' else hashlib.md5()
        with open(sanitized, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except PermissionError:
        log_event(f"Permission denied: {filepath}", "WARNING")
        return None
    except Exception as e:
        log_event(f"Hash calculation error: {e}", "ERROR")
        return None

def get_file_size(filepath: str) -> str:
    """Return human-readable file size."""
    try:
        size = os.path.getsize(filepath)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    except Exception:
        return "Unknown"

# ============================================================================
# BANNER
# ============================================================================

def print_banner():
    """Display banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║    ███████╗██████╗  █████╗ ███╗   ██╗██╗  ██╗███████╗███╗   ██╗ ║
║    ██╔════╝██╔══██╗██╔══██╗████╗  ██║██║ ██╔╝██╔════╝████╗  ██║ ║
║    █████╗  ██████╔╝███████║██╔██╗ ██║█████╔╝ █████╗  ██╔██╗ ██║ ║
║    ██╔══╝  ██╔══██╗██╔══██║██║╚██╗██║██╔═██╗ ██╔══╝  ██║╚██╗██║ ║
║    ██║     ██║  ██║██║  ██║██║ ╚████║██║  ██╗███████╗██║ ╚████║ ║
║    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ║
║                                                                   ║
║              FRANKENSTEIN AV v9.0 - TERMUX EDITION               ║
║                    Advanced Mobile Security                       ║
╚═══════════════════════════════════════════════════════════════════╝
"""
    
    print(f"{Colors.OKCYAN}{banner}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}        📱 Termux Security Suite | Mobile Protection 📱{Colors.ENDC}")
    print(f"{Colors.WARNING}        🔒 Use Responsibly | Educational Use Only 🔒{Colors.ENDC}")
    print(f"{Colors.OKBLUE}        System: {platform.system()} | Python {platform.python_version()}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}        📂 Working Directory: {SCRIPT_DIR}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}        🔬 Version: 9.0 (Termux Edition){Colors.ENDC}")
    if IS_ROOTED:
        print(f"{Colors.WARNING}        🔓 Device Status: ROOTED (Firewall Available){Colors.ENDC}")
    else:
        print(f"{Colors.OKBLUE}        🔒 Device Status: Non-rooted (Firewall requires root){Colors.ENDC}")
    print()

# ============================================================================
# QUARANTINE
# ============================================================================

def quarantine_file(filepath: str) -> bool:
    """Move file to quarantine."""
    sanitized = sanitize_path(filepath)
    if not sanitized:
        return False
    
    try:
        filename = os.path.basename(sanitized)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{timestamp}_{filename}")
        
        shutil.move(sanitized, quarantine_path)
        
        # Create metadata
        metadata = {
            'original_path': sanitized,
            'quarantine_date': timestamp,
            'file_hash': calculate_file_hash(quarantine_path),
            'file_size': get_file_size(quarantine_path)
        }
        with open(f"{quarantine_path}.meta", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"{Colors.OKGREEN}🔒 Quarantined: {quarantine_path}{Colors.ENDC}")
        log_event(f"File quarantined: {filepath}", "QUARANTINE")
        return True
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Quarantine error: {e}{Colors.ENDC}")
        log_event(f"Quarantine error: {e}", "ERROR")
        return False

# ============================================================================
# REPORT GENERATION
# ============================================================================

def save_scan_report(report_data: str, report_type: str = "scan") -> Optional[str]:
    """Save scan report."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = os.path.join(REPORTS_DIR, f"{report_type}_report_{timestamp}.txt")
    
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write(f"Frankenstein AV v9.0 - Termux Edition - {report_type.upper()} REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
            f.write(report_data)
        
        print(f"{Colors.OKGREEN}📄 Report saved: {report_file}{Colors.ENDC}")
        log_event(f"Report saved: {report_file}", "INFO")
        return report_file
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Report save error: {e}{Colors.ENDC}")
        return None

# ============================================================================
# HASH DATABASE MANAGEMENT
# ============================================================================

def load_hash_database() -> Dict[str, str]:
    """Load hashes from SQLite, fallback to JSON."""
    hashes = {}
    
    # Try SQLite first
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT hash, name FROM hashes")
            rows = cursor.fetchall()
            hashes = {row[0]: row[1] for row in rows}
            conn.close()
            if hashes:
                print(f"{Colors.OKGREEN}✅ Loaded {len(hashes)} hashes from SQLite{Colors.ENDC}")
                return hashes
        except Exception as e:
            log_event(f"SQLite load failed: {e}", "WARNING")
            if conn:
                conn.close()
    
    # Fallback to JSON
    all_hashes = LOCAL_MALWARE_HASHES.copy()
    for json_file in [HASH_DB_FILE, CUSTOM_HASH_FILE]:
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    all_hashes.update(data)
            except Exception as e:
                log_event(f"Error loading {json_file}: {e}", "WARNING")
    
    print(f"{Colors.OKGREEN}✅ Loaded {len(all_hashes)} hashes from JSON{Colors.ENDC}")
    return all_hashes

def save_hash_database(hashes: Dict[str, str], custom: bool = False) -> bool:
    """Save hashes to SQLite and JSON."""
    if not hashes:
        return False
    
    try:
        # SQLite
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            for h, name in hashes.items():
                if validate_hash(h):
                    cursor.execute("""
                        INSERT OR REPLACE INTO hashes (hash, name, source, date_added)
                        VALUES (?, ?, ?, ?)
                    """, (h.lower(), name, "Imported", datetime.now().isoformat()))
            conn.commit()
            conn.close()
            print(f"{Colors.OKGREEN}✅ Saved {len(hashes)} hashes to SQLite{Colors.ENDC}")
        
        # JSON backup
        target_file = CUSTOM_HASH_FILE if custom else HASH_DB_FILE
        with open(target_file, 'w') as f:
            json.dump(hashes, f, indent=2)
        
        return True
    except Exception as e:
        print(f"{Colors.FAIL}❌ Save failed: {e}{Colors.ENDC}")
        return False

@retry_on_failure(retries=3, delay=5)
def update_malware_database():
    """Download and update malware hashes."""
    print(f"\n{Colors.BOLD}🔄 Malware Database Update{Colors.ENDC}")
    new_hashes = {}
    
    try:
        response = requests.get(MALWARE_HASH_SOURCES["malwarebazaar"], timeout=30)
        response.raise_for_status()
        
        hashes = [line.strip() for line in response.text.splitlines() 
                  if line.strip() and not line.startswith('#') and len(line.strip()) == 64]
        
        for h in hashes[:1000]:
            if validate_hash(h):
                new_hashes[h] = "MalwareBazaar Detected Threat"
        
        print(f"{Colors.OKGREEN}✅ Downloaded {len(new_hashes)} hashes{Colors.ENDC}")
        
        if new_hashes:
            save_hash_database(new_hashes)
            log_event(f"Database updated: {len(new_hashes)} hashes", "INFO")
        
    except Exception as e:
        print(f"{Colors.FAIL}❌ Update failed: {e}{Colors.ENDC}")
        log_event(f"Database update error: {e}", "ERROR")

# ============================================================================
# SCANNING FUNCTIONS
# ============================================================================

def check_hash_in_databases(file_hash: str) -> Tuple[bool, Optional[str], str]:
    """Check hash against databases."""
    if not validate_hash(file_hash):
        return False, None, "Invalid"
    
    # Check SQLite
    result = db_check_hash(file_hash)
    if result:
        return True, result[0], "SQLite"
    
    # Check JSON fallback
    json_hashes = load_hash_database()
    if file_hash in json_hashes:
        return True, json_hashes[file_hash], "JSON"
    
    return False, None, "None"

def scan_file_local_hash(filepath: str) -> Optional[Dict]:
    """Scan file against local hash database."""
    sanitized = sanitize_path(filepath)
    if not sanitized:
        print(f"{Colors.FAIL}📁 File not found{Colors.ENDC}")
        return None
    
    print(f"{Colors.OKBLUE}🔍 Scanning '{os.path.basename(sanitized)}'...{Colors.ENDC}")
    
    file_hash_sha256 = calculate_file_hash(sanitized, 'sha256')
    file_hash_md5 = calculate_file_hash(sanitized, 'md5')
    
    if not file_hash_sha256 or not file_hash_md5:
        print(f"{Colors.FAIL}❌ Failed to calculate hash{Colors.ENDC}")
        return None
    
    threat_found = False
    threat_name = None
    source = None
    
    for h in [file_hash_sha256, file_hash_md5]:
        found, name, src = check_hash_in_databases(h)
        if found:
            threat_found = True
            threat_name = name
            source = src
            break
    
    if threat_found:
        print(f"{Colors.FAIL}🚨 MALICIOUS: {threat_name} ({source}){Colors.ENDC}")
        log_event(f"Threat detected: {filepath} - {threat_name}", "ALERT")
        
        quarantine = input(f"\n{Colors.WARNING}🔒 Quarantine? (y/N): {Colors.ENDC}").lower()
        if quarantine == 'y':
            quarantine_file(sanitized)
    else:
        print(f"{Colors.OKGREEN}✅ No threats detected{Colors.ENDC}")
        log_event(f"File scanned clean: {filepath}", "INFO")
    
    return {
        "file": sanitized,
        "sha256": file_hash_sha256,
        "md5": file_hash_md5,
        "threat_found": threat_found,
        "threat_name": threat_name or "None",
        "source": source or "None"
    }

@retry_on_failure(retries=2, delay=3)
def scan_file_virustotal(filepath: str) -> Optional[Dict]:
    """Scan file with VirusTotal."""
    if not VT_API_KEY:
        print(f"{Colors.FAIL}⚠️  VT API Key not configured{Colors.ENDC}")
        return None
    
    sanitized = sanitize_path(filepath)
    if not sanitized:
        return None
    
    file_hash = calculate_file_hash(sanitized)
    if not file_hash:
        return None
    
    print(f"{Colors.OKBLUE}🔍 Scanning with VirusTotal...{Colors.ENDC}")
    
    rate_limit_vt()
    
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            print(f"\n{Colors.OKCYAN}📊 VirusTotal Report:{Colors.ENDC}")
            print(f"  🔴 Malicious: {malicious}")
            print(f"  🟡 Suspicious: {suspicious}")
            print(f"  🟢 Undetected: {stats.get('undetected', 0)}")
            
            if malicious > 0:
                print(f"\n{Colors.FAIL}🚨 MALICIOUS FILE!{Colors.ENDC}")
                log_event(f"VT malicious: {filepath} ({malicious})", "ALERT")
                
                quarantine = input(f"\n{Colors.WARNING}🔒 Quarantine? (y/N): {Colors.ENDC}").lower()
                if quarantine == 'y':
                    quarantine_file(sanitized)
            
            return {
                'file': sanitized,
                'hash': file_hash,
                'malicious': malicious,
                'suspicious': suspicious
            }
        
        elif response.status_code == 404:
            print(f"{Colors.WARNING}🔍 Hash not found{Colors.ENDC}")
            return None
        
        else:
            print(f"{Colors.FAIL}⚠️  VT API error: {response.status_code}{Colors.ENDC}")
            return None
    
    except Exception as e:
        print(f"{Colors.FAIL}🌐 Error: {e}{Colors.ENDC}")
        log_event(f"VT scan error: {e}", "ERROR")
        return None

def scan_directory(directory_path: str, recursive: bool = True):
    """Scan directory for malware."""
    sanitized = sanitize_path(directory_path)
    if not sanitized or not os.path.isdir(sanitized):
        print(f"{Colors.FAIL}❌ Invalid directory{Colors.ENDC}")
        return
    
    print(f"\n{Colors.OKBLUE}📂 Scanning: {sanitized}{Colors.ENDC}")
    
    file_list = []
    try:
        if recursive:
            for root, _, files in os.walk(sanitized):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    if os.path.isfile(filepath):
                        file_list.append(filepath)
        else:
            for item in os.listdir(sanitized):
                filepath = os.path.join(sanitized, item)
                if os.path.isfile(filepath):
                    file_list.append(filepath)
    except PermissionError:
        print(f"{Colors.FAIL}⚠️  Permission denied{Colors.ENDC}")
        return
    
    if not file_list:
        print(f"{Colors.WARNING}⚠️  No files found{Colors.ENDC}")
        return
    
    scanned = 0
    threats = 0
    skipped = 0
    results = []
    
    with tqdm(total=len(file_list), desc="Scanning", unit="file") as pbar:
        for filepath in file_list:
            pbar.set_description(f"Scanning: {os.path.basename(filepath)[:30]}")
            
            file_hash = calculate_file_hash(filepath)
            if not file_hash:
                skipped += 1
                results.append(f"SKIPPED: {filepath}")
                pbar.update(1)
                continue
            
            found, name, source = check_hash_in_databases(file_hash)
            scanned += 1
            
            if found:
                threats += 1
                results.append(f"THREAT: {filepath} - {name}")
                pbar.write(f"{Colors.FAIL}🚨 {os.path.basename(filepath)}{Colors.ENDC}")
            else:
                results.append(f"CLEAN: {filepath}")
            
            pbar.update(1)
    
    print(f"\n{Colors.OKGREEN}📊 Scan Complete!{Colors.ENDC}")
    print(f"  📁 Scanned: {scanned}")
    print(f"  🚨 Threats: {threats}")
    print(f"  ✅ Clean: {scanned - threats}")
    print(f"  ⏭️  Skipped: {skipped}")
    
    report_data = f"Directory: {directory_path}\nScanned: {scanned}\nThreats: {threats}\n\n"
    report_data += "\n".join(results)
    save_scan_report(report_data, "directory_scan")

# ============================================================================
# PATCH 1: QUICK SCAN MENU WITH PRESET PATHS
# ============================================================================
def quick_scan_menu():
    """User-friendly quick scan with preset paths - FIXED VERSION."""
    print(f"\n{Colors.BOLD}⚡ Quick Scan Menu{Colors.ENDC}\n")
    
    # Preset important Android/Termux paths
    preset_paths = {
        "1": {
            "name": "📥 Downloads Folder",
            "path": os.path.expanduser("~/storage/downloads"),
            "alt_paths": ["/sdcard/Download", "/storage/emulated/0/Download"],
            "description": "Scan downloaded files"
        },
        "2": {
            "name": "📱 SD Card Root",
            "path": "/sdcard",
            "alt_paths": ["/storage/emulated/0", "/storage/self/primary"],
            "description": "Scan entire SD card (may take time)"
        },
        "3": {
            "name": "📂 Termux Home",
            "path": os.path.expanduser("~"),
            "alt_paths": ["/data/data/com.termux/files/home"],
            "description": "Scan Termux installation"
        },
        "4": {
            "name": "📸 DCIM (Camera)",
            "path": "/sdcard/DCIM",
            "alt_paths": ["/storage/emulated/0/DCIM"],
            "description": "Scan camera photos"
        },
        "5": {
            "name": "🎵 Music Folder",
            "path": "/sdcard/Music",
            "alt_paths": ["/storage/emulated/0/Music"],
            "description": "Scan music files"
        },
        "6": {
            "name": "📄 Documents",
            "path": "/sdcard/Documents",
            "alt_paths": ["/storage/emulated/0/Documents"],
            "description": "Scan documents"
        },
        "7": {
            "name": "💾 External Storage",
            "path": "/storage",
            "alt_paths": ["/mnt"],
            "description": "Scan all external storage"
        },
        "8": {
            "name": "🌐 WhatsApp Media",
            "path": "/sdcard/WhatsApp",
            "alt_paths": ["/storage/emulated/0/WhatsApp"],
            "description": "Scan WhatsApp files"
        },
        "9": {
            "name": "📦 APK Files",
            "path": None,  # Special handler
            "alt_paths": [],
            "description": "Scan all APK files on device"
        },
    }
    
    print(f"{Colors.OKCYAN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}🎯 Select what to scan:{Colors.ENDC}\n")
    
    # Display available paths with better checking
    available_paths = []
    for key, info in preset_paths.items():
        if info["path"] is None:  # APK scan
            status = f"{Colors.OKGREEN}✅{Colors.ENDC}"
            available_paths.append(key)
        else:
            # Check main path and alternatives
            found_path = None
            if os.path.exists(info["path"]) and os.access(info["path"], os.R_OK):
                found_path = info["path"]
            else:
                # Check alternative paths
                for alt_path in info["alt_paths"]:
                    if os.path.exists(alt_path) and os.access(alt_path, os.R_OK):
                        found_path = alt_path
                        break
            
            if found_path:
                status = f"{Colors.OKGREEN}✅{Colors.ENDC}"
                available_paths.append(key)
                # Update path to working one
                preset_paths[key]["working_path"] = found_path
            else:
                status = f"{Colors.FAIL}❌{Colors.ENDC}"
        
        print(f"  {status} {key}. {info['name']}")
        print(f"      {Colors.OKCYAN}{info['description']}{Colors.ENDC}")
        if info["path"]:
            display_path = preset_paths[key].get("working_path", info["path"])
            print(f"      {Colors.WARNING}Path: {display_path}{Colors.ENDC}")
        print()
    
    print(f"  {Colors.OKBLUE}📁 0. Custom Path{Colors.ENDC}")
    print(f"  {Colors.OKBLUE}🎯 M. Multi-Select (scan multiple){Colors.ENDC}")
    print(f"  {Colors.OKBLUE}🔙 B. Back to main menu{Colors.ENDC}")
    
    print(f"\n{Colors.OKCYAN}{'='*70}{Colors.ENDC}")
    
    choice = input(f"{Colors.OKCYAN}👉 Your choice: {Colors.ENDC}").strip().upper()
    
    if choice == 'B':
        return
    
    elif choice == 'M':
        # Multi-select mode
        print(f"\n{Colors.OKBLUE}📋 Multi-Select Mode{Colors.ENDC}")
        print(f"{Colors.WARNING}Enter numbers separated by spaces (e.g., 1 2 3){Colors.ENDC}")
        print(f"{Colors.OKCYAN}Available: {', '.join(available_paths)}{Colors.ENDC}")
        multi_choice = input(f"{Colors.OKCYAN}👉 Paths to scan: {Colors.ENDC}").strip().split()
        
        paths_to_scan = []
        for c in multi_choice:
            if c in available_paths and c in preset_paths:
                if c == "9":  # APK scan
                    print(f"\n{Colors.WARNING}⚠️  APK scan must be done separately{Colors.ENDC}")
                    continue
                
                scan_path = preset_paths[c].get("working_path", preset_paths[c]["path"])
                if scan_path:
                    paths_to_scan.append((preset_paths[c]["name"], scan_path))
        
        if not paths_to_scan:
            print(f"{Colors.WARNING}⚠️  No valid paths selected{Colors.ENDC}")
            return
        
        # Scan all selected paths
        print(f"\n{Colors.OKGREEN}🚀 Scanning {len(paths_to_scan)} locations...{Colors.ENDC}\n")
        
        all_results = {
            'total_scanned': 0,
            'total_threats': 0,
            'total_clean': 0,
            'total_skipped': 0,
            'threat_files': []
        }
        
        for name, scan_path in paths_to_scan:
            print(f"\n{Colors.OKBLUE}{'='*70}{Colors.ENDC}")
            print(f"{Colors.OKBLUE}📂 Scanning: {name} ({scan_path}){Colors.ENDC}")
            print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}\n")
            
            results = scan_directory_with_threat_action(scan_path, recursive=True)
            if results:
                all_results['total_scanned'] += results['scanned']
                all_results['total_threats'] += results['threats']
                all_results['total_clean'] += results['clean']
                all_results['total_skipped'] += results['skipped']
                all_results['threat_files'].extend(results.get('threat_files', []))
        
        # Final summary
        print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}📊 Multi-Scan Complete!{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"  📁 Total Scanned: {all_results['total_scanned']:,}")
        print(f"  🚨 Total Threats: {all_results['total_threats']:,}")
        print(f"  ✅ Total Clean: {all_results['total_clean']:,}")
        print(f"  ⏭️  Total Skipped: {all_results['total_skipped']:,}")
        print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
        
        # Handle all threats at once
        if all_results['threat_files']:
            handle_multiple_threats(all_results['threat_files'])
    
    elif choice == '0':
        # Custom path
        custom_path = input(f"\n{Colors.OKCYAN}📁 Enter custom path: {Colors.ENDC}").strip()
        if custom_path and os.path.exists(custom_path):
            recursive = input(f"{Colors.OKCYAN}Recursive scan? (Y/n): {Colors.ENDC}").strip().lower() != 'n'
            scan_directory_with_threat_action(custom_path, recursive)
        else:
            print(f"{Colors.FAIL}❌ Invalid path or path does not exist{Colors.ENDC}")
    
    elif choice in available_paths:
        # Single preset path
        selected = preset_paths[choice]
        
        if choice == "9":  # APK scan
            scan_apk_directory()
            return
        
        scan_path = selected.get("working_path", selected["path"])
        
        if not scan_path or not os.path.exists(scan_path):
            print(f"{Colors.FAIL}❌ Path not accessible{Colors.ENDC}")
            return
        
        # Confirmation for large scans
        if choice in ["2", "7"]:  # SD card or external storage
            print(f"\n{Colors.WARNING}⚠️  Warning: This may take a long time!{Colors.ENDC}")
            file_count_estimate = sum(1 for _ in Path(scan_path).rglob('*') if _.is_file())
            print(f"{Colors.OKCYAN}Estimated files: ~{file_count_estimate:,}{Colors.ENDC}")
            confirm = input(f"{Colors.WARNING}Continue? (y/N): {Colors.ENDC}").strip().lower()
            if confirm != 'y':
                return
        
        # Ask recursive option for smaller paths
        recursive = True
        if choice not in ["2", "7"]:
            recursive = input(f"{Colors.OKCYAN}Scan subfolders? (Y/n): {Colors.ENDC}").strip().lower() != 'n'
        
        # Perform scan
        scan_directory_with_threat_action(scan_path, recursive)
    
    else:
        print(f"{Colors.WARNING}⚠️  Invalid choice{Colors.ENDC}")

def scan_directory_with_threat_action(directory_path: str, recursive: bool = True) -> dict:
    """Scan directory with real-time threat action prompts - FIXED SAFE VERSION."""
    sanitized = sanitize_path(directory_path)
    if not sanitized or not os.path.isdir(sanitized):
        print(f"{Colors.FAIL}❌ Invalid directory{Colors.ENDC}")
        return None
    
    print(f"\n{Colors.OKBLUE}🔍 Scanning: {sanitized}{Colors.ENDC}")
    
    # Collect files
    file_list = []
    try:
        if recursive:
            for root, _, files in os.walk(sanitized):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    if os.path.isfile(filepath):
                        file_list.append(filepath)
        else:
            for item in os.listdir(sanitized):
                filepath = os.path.join(sanitized, item)
                if os.path.isfile(filepath):
                    file_list.append(filepath)
    except PermissionError:
        print(f"{Colors.FAIL}⚠️  Permission denied accessing some files{Colors.ENDC}")
        return None
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")
        return None
    
    if not file_list:
        print(f"{Colors.WARNING}⚠️  No files found{Colors.ENDC}")
        return None
    
    print(f"{Colors.OKGREEN}📊 Found {len(file_list):,} files to scan{Colors.ENDC}")
    print(f"{Colors.OKCYAN}💡 Scanning only - NO files will be modified during scan{Colors.ENDC}\n")
    
    scanned = 0
    threats = 0
    skipped = 0
    threat_files = []
    results = []
    
    # CRITICAL FIX: Scanning ONLY - NO file modification during scan
    with tqdm(total=len(file_list), desc="Scanning", unit="file") as pbar:
        for filepath in file_list:
            pbar.set_description(f"Scanning: {os.path.basename(filepath)[:30]}")
            
            file_hash = calculate_file_hash(filepath)
            if not file_hash:
                skipped += 1
                results.append(f"SKIPPED: {filepath}")
                pbar.update(1)
                continue
            
            found, name, source = check_hash_in_databases(file_hash)
            scanned += 1
            
            if found:
                threats += 1
                threat_files.append({
                    'path': filepath,
                    'name': name,
                    'hash': file_hash,
                    'source': source
                })
                results.append(f"THREAT: {filepath} - {name}")
                pbar.write(f"{Colors.FAIL}🚨 THREAT DETECTED: {os.path.basename(filepath)} - {name}{Colors.ENDC}")
            else:
                results.append(f"CLEAN: {filepath}")
            
            pbar.update(1)
    
    # Summary
    print(f"\n{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}📊 Scan Complete!{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
    print(f"  📁 Files Scanned: {scanned:,}")
    print(f"  🚨 Threats Found: {threats:,}")
    print(f"  ✅ Clean Files: {scanned - threats:,}")
    print(f"  ⏭️  Files Skipped: {skipped:,}")
    print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}\n")
    
    # CRITICAL: Only ask for action AFTER scan is complete
    if threat_files:
        print(f"{Colors.OKCYAN}💡 Scan complete. Now you can decide what to do with the threats.{Colors.ENDC}")
        print(f"{Colors.OKGREEN}✅ NO files have been modified yet.{Colors.ENDC}\n")
        handle_multiple_threats(threat_files)
    else:
        print(f"{Colors.OKGREEN}🎉 No threats found! Your files are safe.{Colors.ENDC}\n")
    
    # Save report
    report_data = f"Directory: {directory_path}\n"
    report_data += f"Scanned: {scanned}\nThreats: {threats}\nClean: {scanned-threats}\nSkipped: {skipped}\n\n"
    report_data += "\n".join(results)
    save_scan_report(report_data, "directory_scan")
    
    return {
        'scanned': scanned,
        'threats': threats,
        'clean': scanned - threats,
        'skipped': skipped,
        'threat_files': threat_files
    }

def handle_multiple_threats(threat_files: list):
    """Handle multiple detected threats with user actions - FIXED VERSION."""
    if not threat_files:
        return
    
    print(f"\n{Colors.FAIL}{'='*70}{Colors.ENDC}")
    print(f"{Colors.FAIL}🚨 THREAT DETECTED - ACTION REQUIRED{Colors.ENDC}")
    print(f"{Colors.FAIL}{'='*70}{Colors.ENDC}\n")
    
    print(f"{Colors.WARNING}Found {len(threat_files)} threat(s):{Colors.ENDC}\n")
    
    # List all threats
    for idx, threat in enumerate(threat_files, 1):
        print(f"{Colors.FAIL}{idx}. {os.path.basename(threat['path'])}{Colors.ENDC}")
        print(f"   📁 Path: {threat['path']}")
        print(f"   🚨 Threat: {threat['name']}")
        print(f"   🔍 Source: {threat['source']}")
        print()
    
    print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}What would you like to do with these threats?{Colors.ENDC}\n")
    print(f"  {Colors.FAIL}1. 🗑️  DELETE - Permanently remove all threats{Colors.ENDC}")
    print(f"  {Colors.WARNING}2. 🧹 CLEAN - Attempt to clean/repair files (not recommended){Colors.ENDC}")
    print(f"  {Colors.OKBLUE}3. 🔒 QUARANTINE - Move all threats to quarantine (SAFE){Colors.ENDC}")
    print(f"  {Colors.OKGREEN}4. 📋 INDIVIDUAL - Handle each threat separately{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}5. ⏭️  SKIP - Do nothing (keep files as is){Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
    
    # CRITICAL FIX: Add input validation loop
    action = None
    while action not in ['1', '2', '3', '4', '5']:
        action = input(f"\n{Colors.OKCYAN}👉 Your choice (1-5): {Colors.ENDC}").strip()
        
        if action not in ['1', '2', '3', '4', '5']:
            print(f"{Colors.FAIL}❌ Invalid choice! Please enter 1, 2, 3, 4, or 5{Colors.ENDC}")
    
    # CRITICAL FIX: Explicit action handling
    if action == '1':
        # DELETE ALL - Requires confirmation
        print(f"\n{Colors.WARNING}{'='*70}{Colors.ENDC}")
        print(f"{Colors.WARNING}⚠️  WARNING: This will PERMANENTLY DELETE {len(threat_files)} file(s)!{Colors.ENDC}")
        print(f"{Colors.WARNING}⚠️  This action CANNOT be undone!{Colors.ENDC}")
        print(f"{Colors.WARNING}{'='*70}{Colors.ENDC}")
        
        confirm = input(f"\n{Colors.WARNING}Type 'DELETE' to confirm (or anything else to cancel): {Colors.ENDC}")
        
        if confirm == 'DELETE':
            print(f"\n{Colors.OKBLUE}Deleting threats...{Colors.ENDC}")
            deleted = 0
            failed = 0
            for threat in threat_files:
                try:
                    if os.path.exists(threat['path']):
                        os.remove(threat['path'])
                        print(f"{Colors.OKGREEN}✅ Deleted: {os.path.basename(threat['path'])}{Colors.ENDC}")
                        deleted += 1
                        log_event(f"File deleted: {threat['path']}", "ACTION")
                    else:
                        print(f"{Colors.WARNING}⚠️  File not found: {os.path.basename(threat['path'])}{Colors.ENDC}")
                        failed += 1
                except Exception as e:
                    print(f"{Colors.FAIL}❌ Failed to delete {os.path.basename(threat['path'])}: {e}{Colors.ENDC}")
                    failed += 1
                    log_event(f"Delete failed: {threat['path']} - {e}", "ERROR")
            
            print(f"\n{Colors.OKGREEN}✅ Deleted: {deleted}/{len(threat_files)}{Colors.ENDC}")
            if failed > 0:
                print(f"{Colors.WARNING}⚠️  Failed: {failed}{Colors.ENDC}")
        else:
            print(f"\n{Colors.OKGREEN}✅ Delete cancelled - No files were deleted{Colors.ENDC}")
    
    elif action == '2':
        # CLEAN ALL - Show warning
        print(f"\n{Colors.WARNING}{'='*70}{Colors.ENDC}")
        print(f"{Colors.WARNING}⚠️  IMPORTANT: Most malware CANNOT be safely cleaned{Colors.ENDC}")
        print(f"{Colors.WARNING}⚠️  Cleaning may damage files or leave malware active{Colors.ENDC}")
        print(f"{Colors.WARNING}⚠️  Recommended action: Quarantine or Delete{Colors.ENDC}")
        print(f"{Colors.WARNING}{'='*70}{Colors.ENDC}")
        
        proceed = input(f"\n{Colors.OKCYAN}Proceed with cleaning anyway? (y/N): {Colors.ENDC}").strip().lower()
        
        if proceed == 'y':
            print(f"\n{Colors.OKBLUE}Attempting to clean threats...{Colors.ENDC}")
            cleaned = 0
            failed = 0
            for threat in threat_files:
                print(f"{Colors.WARNING}⚠️  Cannot clean: {os.path.basename(threat['path'])}{Colors.ENDC}")
                print(f"   Reason: No safe cleaning method available for this threat type")
                failed += 1
            
            print(f"\n{Colors.WARNING}⚠️  Could not clean: {failed} file(s){Colors.ENDC}")
            print(f"{Colors.OKCYAN}💡 Recommendation: Use Quarantine (option 3) or Delete (option 1){Colors.ENDC}")
            log_event(f"Clean attempted: {failed} files could not be cleaned", "WARNING")
        else:
            print(f"\n{Colors.OKGREEN}✅ Cleaning cancelled{Colors.ENDC}")
    
    elif action == '3':
        # QUARANTINE ALL - Safe option
        print(f"\n{Colors.OKBLUE}Quarantining threats...{Colors.ENDC}")
        quarantined = 0
        failed = 0
        
        for threat in threat_files:
            try:
                if quarantine_file(threat['path']):
                    quarantined += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"{Colors.FAIL}❌ Quarantine failed for {os.path.basename(threat['path'])}: {e}{Colors.ENDC}")
                failed += 1
        
        print(f"\n{Colors.OKGREEN}✅ Quarantined: {quarantined}/{len(threat_files)}{Colors.ENDC}")
        if failed > 0:
            print(f"{Colors.WARNING}⚠️  Failed: {failed}{Colors.ENDC}")
        log_event(f"Bulk quarantine: {quarantined} threats isolated", "ACTION")
    
    elif action == '4':
        # INDIVIDUAL HANDLING
        handle_threats_individually(threat_files)
    
    elif action == '5':
        # SKIP - Do nothing
        print(f"\n{Colors.OKGREEN}✅ Action skipped - No files were modified{Colors.ENDC}")
        print(f"{Colors.WARNING}⚠️  Threats remain on your system!{Colors.ENDC}")
        print(f"{Colors.OKCYAN}💡 You can scan again and choose to quarantine or delete them later{Colors.ENDC}")
        log_event(f"User skipped action for {len(threat_files)} threats", "WARNING")

def handle_threats_individually(threat_files: list):
    """Handle each threat one by one - FIXED VERSION."""
    print(f"\n{Colors.BOLD}📋 Individual Threat Handling{Colors.ENDC}\n")
    print(f"{Colors.OKCYAN}You will be asked what to do with each threat separately{Colors.ENDC}\n")
    
    for idx, threat in enumerate(threat_files, 1):
        print(f"{Colors.OKCYAN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.FAIL}Threat {idx}/{len(threat_files)}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{'='*70}{Colors.ENDC}")
        print(f"📁 File: {os.path.basename(threat['path'])}")
        print(f"📂 Location: {os.path.dirname(threat['path'])}")
        print(f"🚨 Threat: {threat['name']}")
        print(f"💾 Size: {get_file_size(threat['path'])}")
        print(f"🔍 Detection: {threat['source']}")
        
        print(f"\n{Colors.OKCYAN}Actions:{Colors.ENDC}")
        print(f"  1. 🗑️  Delete this file")
        print(f"  2. 🔒 Quarantine this file")
        print(f"  3. ⏭️  Skip this file (leave as is)")
        print(f"  4. ⏸️  Cancel (skip all remaining)")
        
        # CRITICAL FIX: Input validation
        action = None
        while action not in ['1', '2', '3', '4']:
            action = input(f"\n{Colors.OKCYAN}Action for this file (1-4): {Colors.ENDC}").strip()
            
            if action not in ['1', '2', '3', '4']:
                print(f"{Colors.FAIL}❌ Invalid! Please enter 1, 2, 3, or 4{Colors.ENDC}")
        
        # CRITICAL FIX: Explicit action handling
        if action == '1':
            # Delete with confirmation
            confirm = input(f"{Colors.WARNING}Delete {os.path.basename(threat['path'])}? (y/N): {Colors.ENDC}").strip().lower()
            
            if confirm == 'y':
                try:
                    if os.path.exists(threat['path']):
                        os.remove(threat['path'])
                        print(f"{Colors.OKGREEN}✅ Deleted{Colors.ENDC}")
                        log_event(f"File deleted: {threat['path']}", "ACTION")
                    else:
                        print(f"{Colors.WARNING}⚠️  File not found{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.FAIL}❌ Delete failed: {e}{Colors.ENDC}")
                    log_event(f"Delete failed: {threat['path']} - {e}", "ERROR")
            else:
                print(f"{Colors.OKGREEN}✅ Delete cancelled{Colors.ENDC}")
        
        elif action == '2':
            # Quarantine
            try:
                if quarantine_file(threat['path']):
                    print(f"{Colors.OKGREEN}✅ Quarantined{Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}❌ Quarantine failed{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}❌ Quarantine failed: {e}{Colors.ENDC}")
        
        elif action == '3':
            # Skip
            print(f"{Colors.OKGREEN}✅ Skipped - File left as is{Colors.ENDC}")
        
        elif action == '4':
            # Cancel all
            print(f"\n{Colors.WARNING}⏸️  Cancelled - Skipping all remaining threats{Colors.ENDC}")
            remaining = len(threat_files) - idx
            if remaining > 0:
                print(f"{Colors.WARNING}⚠️  {remaining} threat(s) were not processed{Colors.ENDC}")
            return
        
        print()


def delete_file(filepath: str) -> bool:
    """Permanently delete a file - SAFE VERSION with confirmation."""
    # THIS FUNCTION SHOULD NEVER BE CALLED WITHOUT USER CONFIRMATION
    # It's only used after explicit user consent
    try:
        if not os.path.exists(filepath):
            print(f"{Colors.WARNING}⚠️  File not found: {filepath}{Colors.ENDC}")
            return False
        
        # Extra safety check
        confirm = input(f"{Colors.WARNING}⚠️  FINAL CONFIRMATION - Delete {os.path.basename(filepath)}? (yes/no): {Colors.ENDC}").strip().lower()
        
        if confirm == 'yes':
            os.remove(filepath)
            print(f"{Colors.OKGREEN}✅ Deleted: {os.path.basename(filepath)}{Colors.ENDC}")
            log_event(f"File deleted: {filepath}", "ACTION")
            return True
        else:
            print(f"{Colors.OKGREEN}✅ Delete cancelled{Colors.ENDC}")
            return False
    except Exception as e:
        print(f"{Colors.FAIL}❌ Delete failed: {e}{Colors.ENDC}")
        log_event(f"Delete failed: {filepath} - {e}", "ERROR")
        return False


def clean_file(filepath: str) -> bool:
    """
    Attempt to clean/repair a file - SAFE VERSION.
    Note: Returns False for all files as safe cleaning is not implemented.
    """
    # IMPORTANT: This function does NOT modify or delete files
    # It only reports that cleaning is not available
    
    print(f"{Colors.WARNING}⚠️  Cleaning not available for: {os.path.basename(filepath)}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}💡 Recommendation: Quarantine or delete this file instead{Colors.ENDC}")
    
    log_event(f"Clean not available: {filepath}", "WARNING")
    return False
    
# ============================================================================
# ANDROID/TERMUX FIREWALL (iptables - requires root)
# ============================================================================

def manage_firewall_iptables():
    """Android iptables firewall management (requires root)."""
    print(f"\n{Colors.BOLD}🔥 Android Firewall Management (iptables){Colors.ENDC}")
    
    if not IS_ROOTED:
        print(f"{Colors.FAIL}❌ Root access required!{Colors.ENDC}")
        print(f"{Colors.WARNING}This feature requires a rooted Android device.{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Root your device to enable firewall features.{Colors.ENDC}")
        input(f"\n{Colors.OKCYAN}Press Enter to continue...{Colors.ENDC}")
        return
    
    print(f"{Colors.OKGREEN}✅ Root access detected{Colors.ENDC}")
    print(f"{Colors.WARNING}⚠️  Warning: Modifying firewall rules can affect connectivity!{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'='*70}{Colors.ENDC}\n")
    
    print(f"{Colors.OKGREEN}Options:{Colors.ENDC}")
    print(f"  1. 📊 Show Current Rules")
    print(f"  2. 🚫 Block IP Address")
    print(f"  3. ✅ Unblock IP Address")
    print(f"  4. 🔒 Block Port")
    print(f"  5. 🔓 Allow Port")
    print(f"  6. 📋 List Blocked IPs")
    print(f"  7. 🗑️  Flush All Rules (Reset)")
    print(f"  8. 🌐 Block from Threat Feed")
    print(f"  0. 🔙 Back")
    
    choice = input(f"\n{Colors.OKCYAN}Choice: {Colors.ENDC}").strip()
    
    if choice == '1':
        print(f"\n{Colors.OKBLUE}📊 Current iptables Rules:{Colors.ENDC}")
        _run_su_cmd(["iptables", "-L", "-n", "-v"], "Fetching rules")
    
    elif choice == '2':
        ip = input(f"{Colors.OKCYAN}IP address to block: {Colors.ENDC}").strip()
        if ip and validate_ip(ip):
            _run_su_cmd(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], f"🚫 Blocking {ip}")
            _run_su_cmd(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], f"🚫 Blocking outbound to {ip}")
            log_event(f"iptables: Blocked IP {ip}", "INFO")
        else:
            print(f"{Colors.FAIL}❌ Invalid IP address{Colors.ENDC}")
    
    elif choice == '3':
        ip = input(f"{Colors.OKCYAN}IP address to unblock: {Colors.ENDC}").strip()
        if ip and validate_ip(ip):
            _run_su_cmd(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], f"✅ Unblocking {ip}")
            _run_su_cmd(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], f"✅ Unblocking outbound to {ip}")
            log_event(f"iptables: Unblocked IP {ip}", "INFO")
        else:
            print(f"{Colors.FAIL}❌ Invalid IP address{Colors.ENDC}")
    
    elif choice == '4':
        port = input(f"{Colors.OKCYAN}Port to block: {Colors.ENDC}").strip()
        protocol = input(f"{Colors.OKCYAN}Protocol (tcp/udp/both) [default: tcp]: {Colors.ENDC}").strip().lower() or 'tcp'
        
        if port:
            if protocol in ['tcp', 'both']:
                _run_su_cmd(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", port, "-j", "DROP"], 
                           f"🔒 Blocking TCP port {port}")
            if protocol in ['udp', 'both']:
                _run_su_cmd(["iptables", "-A", "INPUT", "-p", "udp", "--dport", port, "-j", "DROP"], 
                           f"🔒 Blocking UDP port {port}")
            log_event(f"iptables: Blocked port {port}/{protocol}", "INFO")
    
    elif choice == '5':
        port = input(f"{Colors.OKCYAN}Port to allow: {Colors.ENDC}").strip()
        protocol = input(f"{Colors.OKCYAN}Protocol (tcp/udp/both) [default: tcp]: {Colors.ENDC}").strip().lower() or 'tcp'
        
        if port:
            if protocol in ['tcp', 'both']:
                _run_su_cmd(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", port, "-j", "DROP"], 
                           f"🔓 Allowing TCP port {port}")
            if protocol in ['udp', 'both']:
                _run_su_cmd(["iptables", "-D", "INPUT", "-p", "udp", "--dport", port, "-j", "DROP"], 
                           f"🔓 Allowing UDP port {port}")
            log_event(f"iptables: Allowed port {port}/{protocol}", "INFO")
    
    elif choice == '6':
        print(f"\n{Colors.OKBLUE}📋 Blocked IPs:{Colors.ENDC}")
        _run_su_cmd(["iptables", "-L", "INPUT", "-n", "|", "grep", "DROP"], "")
    
    elif choice == '7':
        confirm = input(f"{Colors.WARNING}⚠️  Flush ALL rules? Type 'FLUSH': {Colors.ENDC}")
        if confirm == 'FLUSH':
            _run_su_cmd(["iptables", "-F"], "🗑️  Flushing all rules")
            _run_su_cmd(["iptables", "-X"], "🗑️  Deleting custom chains")
            log_event("iptables: Flushed all rules", "INFO")
    
    elif choice == '8':
        feed_url = input(f"{Colors.OKCYAN}Feed URL (Enter for default): {Colors.ENDC}").strip() or DEFAULT_THREAT_FEED_URL
        update_iptables_from_threat_feed(feed_url)

def update_iptables_from_threat_feed(feed_url):
    """Update iptables from threat feed."""
    if not IS_ROOTED:
        print(f"{Colors.FAIL}❌ Root required{Colors.ENDC}")
        return
    
    print(f"\n{Colors.OKBLUE}🌐 Fetching threat feed...{Colors.ENDC}")
    log_event(f"iptables threat feed: {feed_url}")
    
    try:
        response = requests.get(feed_url, timeout=15)
        response.raise_for_status()
        
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        malicious_ips = [line.strip().split()[0] for line in response.text.splitlines() 
                        if line.strip() and not line.startswith('#') and ip_pattern.match(line.strip())]
        
        if not malicious_ips:
            print(f"{Colors.WARNING}⚠️  No valid IPs found{Colors.ENDC}")
            return
        
        print(f"{Colors.OKGREEN}✅ Found {len(malicious_ips)} IPs. Applying rules...{Colors.ENDC}")
        
        applied = 0
        for ip in malicious_ips[:100]:  # Limit to 100 for mobile performance
            try:
                subprocess.run(["su", "-c", f"iptables -A INPUT -s {ip} -j DROP"], 
                             capture_output=True, check=True, timeout=5)
                applied += 1
                if applied % 10 == 0:
                    print(f"  📊 Progress: {applied}/{min(100, len(malicious_ips))}", end='\r')
            except:
                pass
        
        print(f"\n{Colors.OKGREEN}✅ Applied {applied} rules{Colors.ENDC}")
        log_event(f"iptables threat feed: {applied} rules applied", "INFO")
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")

def _run_su_cmd(cmd: List[str], message: str):
    """Run command with su (root) access."""
    if message:
        print(f"\n{Colors.OKBLUE}{message}...{Colors.ENDC}")
    
    try:
        full_cmd = ["su", "-c", " ".join(cmd)]
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            if message:
                print(f"{Colors.OKGREEN}✅ Success{Colors.ENDC}")
            if result.stdout.strip():
                print(result.stdout)
            log_event(f"Root command succeeded: {' '.join(cmd)}", "INFO")
        else:
            print(f"{Colors.FAIL}❌ Command failed{Colors.ENDC}")
            if result.stderr.strip():
                print(f"{Colors.FAIL}Error: {result.stderr}{Colors.ENDC}")
            log_event(f"Root command failed: {' '.join(cmd)}", "ERROR")
    
    except subprocess.TimeoutExpired:
        print(f"{Colors.FAIL}❌ Command timed out{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")
        log_event(f"Root command error: {e}", "ERROR")

# ============================================================================
# FILE INTEGRITY MONITORING
# ============================================================================

def file_integrity_monitor_init(target_dir: str) -> Dict:
    """Initialize FIM baseline."""
    sanitized = sanitize_path(target_dir)
    if not sanitized or not os.path.isdir(sanitized):
        print(f"{Colors.FAIL}❌ Invalid directory{Colors.ENDC}")
        return {}
    
    print(f"\n{Colors.OKBLUE}🔧 Initializing FIM...{Colors.ENDC}")
    
    baseline = {}
    file_count = 0
    
    try:
        for root, _, files in os.walk(sanitized):
            for name in files:
                filepath = os.path.join(root, name)
                file_hash = calculate_file_hash(filepath)
                if file_hash:
                    baseline[filepath] = {
                        'hash': file_hash,
                        'size': os.path.getsize(filepath),
                        'modified': os.path.getmtime(filepath)
                    }
                    file_count += 1
                    if file_count % 50 == 0:
                        print(f"  📊 Processed {file_count}...", end='\r')
        
        print()
        
        with open(FIM_DB_FILE, 'wb') as f:
            pickle.dump(baseline, f)
        
        print(f"{Colors.OKGREEN}✅ FIM baseline: {len(baseline)} files{Colors.ENDC}")
        log_event(f"FIM baseline: {len(baseline)} files", "INFO")
        return baseline
    
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")
        return {}

def file_integrity_monitor_check(target_dir: str):
    """Check FIM against baseline."""
    sanitized = sanitize_path(target_dir)
    if not sanitized or not os.path.isdir(sanitized):
        print(f"{Colors.FAIL}❌ Invalid directory{Colors.ENDC}")
        return
    
    if not os.path.exists(FIM_DB_FILE):
        print(f"{Colors.WARNING}⚠️  No baseline found. Initialize first!{Colors.ENDC}")
        return
    
    try:
        with open(FIM_DB_FILE, 'rb') as f:
            baseline = pickle.load(f)
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error loading baseline: {e}{Colors.ENDC}")
        return
    
    print(f"\n{Colors.OKBLUE}🔍 Checking FIM...{Colors.ENDC}")
    
    current_state = {}
    modified_files = []
    new_files = []
    deleted_files = []
    
    for root, _, files in os.walk(sanitized):
        for name in files:
            filepath = os.path.join(root, name)
            file_hash = calculate_file_hash(filepath)
            if file_hash:
                current_state[filepath] = {
                    'hash': file_hash,
                    'size': os.path.getsize(filepath),
                    'modified': os.path.getmtime(filepath)
                }
    
    for filepath, baseline_data in baseline.items():
        if filepath not in current_state:
            deleted_files.append(filepath)
            print(f"{Colors.WARNING}🗑️  [DELETED] {filepath}{Colors.ENDC}")
        elif current_state[filepath]['hash'] != baseline_data['hash']:
            modified_files.append(filepath)
            print(f"{Colors.FAIL}📝 [MODIFIED] {filepath}{Colors.ENDC}")
    
    for filepath in current_state:
        if filepath not in baseline:
            new_files.append(filepath)
            print(f"{Colors.OKGREEN}➕ [NEW] {filepath}{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}📊 FIM Summary:{Colors.ENDC}")
    print(f"  📝 Modified: {len(modified_files)}")
    print(f"  ➕ New: {len(new_files)}")
    print(f"  🗑️  Deleted: {len(deleted_files)}")
    
    report_data = f"Modified: {len(modified_files)}\nNew: {len(new_files)}\nDeleted: {len(deleted_files)}\n\n"
    if modified_files:
        report_data += "MODIFIED:\n" + "\n".join(modified_files) + "\n\n"
    if new_files:
        report_data += "NEW:\n" + "\n".join(new_files) + "\n\n"
    if deleted_files:
        report_data += "DELETED:\n" + "\n".join(deleted_files)
    
    save_scan_report(report_data, "fim_check")

# ============================================================================
# NETWORK FUNCTIONS
# ============================================================================

def check_url_reputation(url: str):
    """Check URL with VirusTotal."""
    if not VT_API_KEY:
        print(f"{Colors.FAIL}⚠️  VT API Key not configured{Colors.ENDC}")
        return
    
    if not validate_url(url):
        print(f"{Colors.FAIL}❌ Invalid URL{Colors.ENDC}")
        return
    
    print(f"\n{Colors.OKBLUE}🌐 Checking URL: {url}{Colors.ENDC}")
    rate_limit_vt()
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes'].get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            
            print(f"\n{Colors.OKCYAN}📊 URL Report:{Colors.ENDC}")
            print(f"  🔴 Malicious: {malicious}")
            print(f"  🟡 Suspicious: {stats.get('suspicious', 0)}")
            
            if malicious > 0:
                print(f"\n{Colors.FAIL}🚨 MALICIOUS URL!{Colors.ENDC}")
                log_event(f"Malicious URL: {url}", "ALERT")
        elif response.status_code == 404:
            print(f"{Colors.WARNING}🔍 URL not in database{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")

def check_ip_reputation(ip: str):
    """Check IP with VirusTotal."""
    if not VT_API_KEY:
        print(f"{Colors.FAIL}⚠️  VT API Key not configured{Colors.ENDC}")
        return
    
    if not validate_ip(ip):
        print(f"{Colors.FAIL}❌ Invalid IP{Colors.ENDC}")
        return
    
    print(f"\n{Colors.OKBLUE}🌐 Checking IP: {ip}{Colors.ENDC}")
    rate_limit_vt()
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes'].get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            
            print(f"\n{Colors.OKCYAN}📊 IP Report:{Colors.ENDC}")
            print(f"  🔴 Malicious: {malicious}")
            
            if malicious > 0:
                print(f"\n{Colors.FAIL}🚨 MALICIOUS IP!{Colors.ENDC}")
                log_event(f"Malicious IP: {ip}", "ALERT")
        elif response.status_code == 404:
            print(f"{Colors.WARNING}🔍 IP not in database{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")

# ============================================================================
# QUARANTINE MANAGEMENT
# ============================================================================

def view_quarantine():
    """View and manage quarantined files."""
    print(f"\n{Colors.BOLD}🔒 Quarantine Management{Colors.ENDC}\n")
    
    try:
        files = [f for f in os.listdir(QUARANTINE_DIR) if not f.endswith('.meta')]
        if not files:
            print(f"{Colors.OKGREEN}✅ Quarantine empty{Colors.ENDC}")
            return
        
        print(f"{Colors.WARNING}📁 Quarantined Files ({len(files)}):{Colors.ENDC}")
        for idx, filename in enumerate(files, 1):
            filepath = os.path.join(QUARANTINE_DIR, filename)
            size = get_file_size(filepath)
            mod_time = datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S')
            print(f"  {idx}. {filename}")
            print(f"      Size: {size} | Date: {mod_time}")
        
        print(f"\n{Colors.OKCYAN}Options:{Colors.ENDC}")
        print(f"  1. 🗑️  Delete all")
        print(f"  2. 🗑️  Delete specific")
        print(f"  3. ↩️  Restore file")
        print(f"  4. 🔙 Back")
        
        choice = input(f"\n{Colors.OKCYAN}Choice: {Colors.ENDC}").strip()
        
        if choice == '1':
            confirm = input(f"{Colors.WARNING}Type 'DELETE': {Colors.ENDC}")
            if confirm == 'DELETE':
                shutil.rmtree(QUARANTINE_DIR)
                os.makedirs(QUARANTINE_DIR)
                print(f"{Colors.OKGREEN}✅ Cleared{Colors.ENDC}")
        
        elif choice == '2':
            try:
                idx = int(input(f"{Colors.OKCYAN}File number: {Colors.ENDC}")) - 1
                if 0 <= idx < len(files):
                    filepath = os.path.join(QUARANTINE_DIR, files[idx])
                    os.remove(filepath)
                    meta_file = f"{filepath}.meta"
                    if os.path.exists(meta_file):
                        os.remove(meta_file)
                    print(f"{Colors.OKGREEN}✅ Deleted{Colors.ENDC}")
            except (ValueError, IndexError):
                print(f"{Colors.FAIL}❌ Invalid{Colors.ENDC}")
        
        elif choice == '3':
            try:
                idx = int(input(f"{Colors.OKCYAN}File number: {Colors.ENDC}")) - 1
                if 0 <= idx < len(files):
                    restore_path = input(f"{Colors.OKCYAN}Restore to: {Colors.ENDC}").strip()
                    if restore_path:
                        filepath = os.path.join(QUARANTINE_DIR, files[idx])
                        shutil.move(filepath, restore_path)
                        print(f"{Colors.OKGREEN}✅ Restored{Colors.ENDC}")
            except (ValueError, IndexError):
                print(f"{Colors.FAIL}❌ Invalid{Colors.ENDC}")
    
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")

# ============================================================================
# LOG AND REPORT VIEWERS
# ============================================================================

def view_logs():
    """Display recent logs."""
    print(f"\n{Colors.BOLD}📜 Log Viewer{Colors.ENDC}\n")
    
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
        
        if not lines:
            print(f"{Colors.WARNING}No logs{Colors.ENDC}")
            return
        
        num_lines = input(f"{Colors.OKCYAN}Show entries (default: 20): {Colors.ENDC}").strip()
        try:
            num_lines = int(num_lines) if num_lines else 20
        except:
            num_lines = 20
        
        print(f"\n{Colors.OKCYAN}Last {num_lines} entries:{Colors.ENDC}")
        print("="*70)
        for line in lines[-num_lines:]:
            if "[ALERT]" in line:
                print(f"{Colors.FAIL}{line.strip()}{Colors.ENDC}")
            elif "[WARNING]" in line:
                print(f"{Colors.WARNING}{line.strip()}{Colors.ENDC}")
            elif "[ERROR]" in line:
                print(f"{Colors.FAIL}{line.strip()}{Colors.ENDC}")
            else:
                print(line.strip())
        print("="*70)
    
    except FileNotFoundError:
        print(f"{Colors.WARNING}⚠️  No log file{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")

def view_reports():
    """Display saved reports."""
    print(f"\n{Colors.BOLD}📄 Report Viewer{Colors.ENDC}\n")
    
    try:
        reports = sorted([f for f in os.listdir(REPORTS_DIR) if f.endswith('.txt')], reverse=True)
        
        if not reports:
            print(f"{Colors.WARNING}No reports{Colors.ENDC}")
            return
        
        print(f"{Colors.OKGREEN}Reports ({len(reports)}):{Colors.ENDC}")
        for idx, report in enumerate(reports[:10], 1):
            print(f"  {idx}. {report}")
        
        choice = input(f"\n{Colors.OKCYAN}Report number (0 to cancel): {Colors.ENDC}").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(reports):
                report_path = os.path.join(REPORTS_DIR, reports[idx])
                with open(report_path, 'r') as f:
                    print(f"\n{Colors.OKCYAN}{'='*70}{Colors.ENDC}")
                    print(f.read())
                    print(f"{Colors.OKCYAN}{'='*70}{Colors.ENDC}")
        except (ValueError, IndexError):
            pass
    
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")

# ============================================================================
# HASH MANAGEMENT
# ============================================================================

def manual_hash_management():
    """Manual hash management."""
    while True:
        print(f"\n{Colors.BOLD}🔧 Hash Management{Colors.ENDC}\n")
        
        conn = get_db_connection()
        total = 0
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM hashes")
                total = cursor.fetchone()[0]
                conn.close()
            except:
                pass
        
        print(f"{Colors.OKGREEN}📊 Total hashes: {total}{Colors.ENDC}\n")
        
        print(f"  1. ➕ Add hash")
        print(f"  2. 📥 Import from file")
        print(f"  3. 🔍 Search hash")
        print(f"  4. 🗑️  Delete hash")
        print(f"  0. 🔙 Back")
        
        choice = input(f"\n{Colors.OKCYAN}Choice: {Colors.ENDC}").strip()
        
        if choice == '1':
            hash_val = input(f"{Colors.OKCYAN}Hash: {Colors.ENDC}").strip()
            if validate_hash(hash_val):
                name = input(f"{Colors.OKCYAN}Name: {Colors.ENDC}").strip()
                if db_add_hash(hash_val, name or "Custom", "Manual"):
                    print(f"{Colors.OKGREEN}✅ Added{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}❌ Invalid hash{Colors.ENDC}")
        
        elif choice == '2':
            filepath = input(f"{Colors.OKCYAN}File: {Colors.ENDC}").strip()
            import_hashes_from_file(filepath)
        
        elif choice == '3':
            hash_val = input(f"{Colors.OKCYAN}Hash: {Colors.ENDC}").strip()
            result = db_check_hash(hash_val)
            if result:
                print(f"{Colors.FAIL}🚨 FOUND: {result[0]}{Colors.ENDC}")
            else:
                print(f"{Colors.OKGREEN}✅ Not found{Colors.ENDC}")
        
        elif choice == '4':
            hash_val = input(f"{Colors.OKCYAN}Hash: {Colors.ENDC}").strip()
            if db_delete_hash(hash_val) > 0:
                print(f"{Colors.OKGREEN}✅ Deleted{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}⚠️  Not found{Colors.ENDC}")
        
        elif choice == '0':
            break
        
        input(f"\n{Colors.OKCYAN}Press Enter...{Colors.ENDC}")

# ============================================================================
# PATCH 2: MIGRATE JSON TO SQLITE (For existing hash databases)
# ============================================================================
def migrate_json_to_sqlite():
    """Migrate JSON hash databases to SQLite."""
    print(f"\n{Colors.BOLD}📦 Migrate JSON → SQLite{Colors.ENDC}\n")
    
    print(f"{Colors.OKCYAN}This will import all JSON hashes into SQLite database.{Colors.ENDC}")
    print(f"{Colors.WARNING}Existing SQLite data will be preserved.{Colors.ENDC}\n")
    
    # Find JSON files
    json_sources = []
    
    if os.path.exists(CUSTOM_HASH_FILE):
        try:
            with open(CUSTOM_HASH_FILE, 'r') as f:
                data = json.load(f)
            json_sources.append(("Custom Hashes", CUSTOM_HASH_FILE, len(data)))
        except:
            pass
    
    if os.path.exists(HASH_DB_FILE):
        try:
            with open(HASH_DB_FILE, 'r') as f:
                data = json.load(f)
            json_sources.append(("Malware Database", HASH_DB_FILE, len(data)))
        except:
            pass
    
    # Add built-in hashes
    json_sources.append(("Built-in Hashes", None, len(LOCAL_MALWARE_HASHES)))
    
    if not json_sources:
        print(f"{Colors.WARNING}⚠️  No JSON files found to migrate{Colors.ENDC}")
        return
    
    print(f"{Colors.OKGREEN}Found JSON sources to migrate:{Colors.ENDC}\n")
    for name, path, count in json_sources:
        print(f"  • {name}: {count} hashes")
        if path:
            print(f"    {Colors.OKCYAN}{path}{Colors.ENDC}")
    
    print(f"\n{Colors.WARNING}⚠️  This may take a few minutes...{Colors.ENDC}")
    confirm = input(f"\n{Colors.OKCYAN}Proceed with migration? (y/N): {Colors.ENDC}").strip().lower()
    
    if confirm != 'y':
        print(f"{Colors.WARNING}Migration cancelled{Colors.ENDC}")
        return
    
    print(f"\n{Colors.OKBLUE}🔄 Starting migration...{Colors.ENDC}\n")
    
    total_added = 0
    duplicates = 0
    errors = 0
    
    # Migrate each source
    for source_name, source_path, _ in json_sources:
        print(f"{Colors.OKCYAN}📥 Processing: {source_name}{Colors.ENDC}")
        
        # Load data
        if source_path:
            try:
                with open(source_path, 'r') as f:
                    hash_data = json.load(f)
            except Exception as e:
                print(f"{Colors.FAIL}❌ Error loading {source_name}: {e}{Colors.ENDC}")
                errors += 1
                continue
        else:
            # Built-in hashes
            hash_data = LOCAL_MALWARE_HASHES
        
        # Import to SQLite
        for hash_val, name in tqdm(hash_data.items(), desc=f"Importing {source_name}", unit="hash"):
            if not validate_hash(hash_val):
                continue
            
            # Check if already exists
            if db_check_hash(hash_val):
                duplicates += 1
            else:
                # Determine source name for database
                db_source = f"JSON:{os.path.basename(source_path)}" if source_path else "Built-in"
                
                if db_add_hash(hash_val, name or "Imported Hash", db_source):
                    total_added += 1
                else:
                    errors += 1
    
    # Final summary
    print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}✅ Migration Complete!{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"  ✅ Imported: {total_added}")
    print(f"  🔄 Duplicates Skipped: {duplicates}")
    print(f"  ❌ Errors: {errors}")
    print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    # Show new database stats
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM hashes")
            total = cursor.fetchone()[0]
            print(f"{Colors.OKGREEN}📊 Total hashes in SQLite: {total:,}{Colors.ENDC}\n")
            conn.close()
        except:
            pass
    
    # Option to backup JSON files
    if total_added > 0:
        backup = input(f"{Colors.OKCYAN}Create backup of JSON files? (Y/n): {Colors.ENDC}").strip().lower()
        if backup != 'n':
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_dir = os.path.join(SCRIPT_DIR, f"json_backup_{timestamp}")
            
            try:
                os.makedirs(backup_dir, exist_ok=True)
                
                for _, source_path, _ in json_sources:
                    if source_path and os.path.exists(source_path):
                        backup_path = os.path.join(backup_dir, os.path.basename(source_path))
                        shutil.copy2(source_path, backup_path)
                
                print(f"{Colors.OKGREEN}✅ Backup created: {backup_dir}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}⚠️  Backup error: {e}{Colors.ENDC}")
    
    log_event(f"JSON to SQLite migration: {total_added} hashes imported", "INFO")

# ============================================================================
# PATCH 3: EXPORT SQLITE TO JSON (Opposite direction)
# ============================================================================
def export_sqlite_to_json():
    """Export SQLite database to JSON file."""
    print(f"\n{Colors.BOLD}📤 Export SQLite → JSON{Colors.ENDC}\n")
    
    conn = get_db_connection()
    if not conn:
        print(f"{Colors.FAIL}❌ Cannot connect to database{Colors.ENDC}")
        return
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM hashes")
        total = cursor.fetchone()[0]
        
        if total == 0:
            print(f"{Colors.WARNING}⚠️  Database is empty{Colors.ENDC}")
            conn.close()
            return
        
        print(f"{Colors.OKGREEN}📊 Total hashes to export: {total:,}{Colors.ENDC}\n")
        
        # Export options
        print(f"{Colors.OKCYAN}Export options:{Colors.ENDC}")
        print(f"  1. 📄 Export all hashes")
        print(f"  2. 📋 Export by source")
        print(f"  0. 🔙 Cancel")
        
        choice = input(f"\n{Colors.OKCYAN}Choice: {Colors.ENDC}").strip()
        
        if choice == '1':
            # Export all
            cursor.execute("SELECT hash, name FROM hashes")
            rows = cursor.fetchall()
            
            export_data = {row[0]: row[1] for row in rows}
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            export_file = os.path.join(SCRIPT_DIR, f"exported_hashes_{timestamp}.json")
            
            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"\n{Colors.OKGREEN}✅ Exported {len(export_data)} hashes to:{Colors.ENDC}")
            print(f"{Colors.OKCYAN}{export_file}{Colors.ENDC}")
        
        elif choice == '2':
            # Export by source
            cursor.execute("SELECT DISTINCT source FROM hashes")
            sources = [row[0] for row in cursor.fetchall()]
            
            print(f"\n{Colors.OKGREEN}Available sources:{Colors.ENDC}")
            for idx, source in enumerate(sources, 1):
                cursor.execute("SELECT COUNT(*) FROM hashes WHERE source=?", (source,))
                count = cursor.fetchone()[0]
                print(f"  {idx}. {source} ({count} hashes)")
            
            src_choice = input(f"\n{Colors.OKCYAN}Select source (1-{len(sources)}): {Colors.ENDC}").strip()
            
            try:
                idx = int(src_choice) - 1
                if 0 <= idx < len(sources):
                    selected_source = sources[idx]
                    
                    cursor.execute("SELECT hash, name FROM hashes WHERE source=?", (selected_source,))
                    rows = cursor.fetchall()
                    
                    export_data = {row[0]: row[1] for row in rows}
                    
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    safe_source = selected_source.replace('/', '_').replace(' ', '_')
                    export_file = os.path.join(SCRIPT_DIR, f"exported_{safe_source}_{timestamp}.json")
                    
                    with open(export_file, 'w') as f:
                        json.dump(export_data, f, indent=2)
                    
                    print(f"\n{Colors.OKGREEN}✅ Exported {len(export_data)} hashes to:{Colors.ENDC}")
                    print(f"{Colors.OKCYAN}{export_file}{Colors.ENDC}")
            except:
                print(f"{Colors.FAIL}❌ Invalid selection{Colors.ENDC}")
        
        conn.close()
        
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")
        if conn:
            conn.close()    

# ============================================================================
# PATCH 7: DATABASE OPTIMIZATION
# ============================================================================
def optimize_sqlite():
    """Optimize SQLite database (VACUUM)."""
    print(f"\n{Colors.BOLD}♻️  Database Optimization{Colors.ENDC}\n")
    
    if not os.path.exists(DB_PATH):
        print(f"{Colors.WARNING}⚠️  Database not found{Colors.ENDC}")
        return
    
    # Show current size
    current_size = os.path.getsize(DB_PATH)
    print(f"{Colors.OKBLUE}📊 Current database size: {get_file_size_bytes(current_size)}{Colors.ENDC}")
    
    print(f"\n{Colors.OKCYAN}This will:{Colors.ENDC}")
    print(f"  • Reclaim unused space")
    print(f"  • Defragment database")
    print(f"  • Rebuild indexes")
    print(f"  • May take a few moments")
    
    confirm = input(f"\n{Colors.OKCYAN}Proceed? (Y/n): {Colors.ENDC}").strip().lower()
    
    if confirm == 'n':
        print(f"{Colors.WARNING}Cancelled{Colors.ENDC}")
        return
    
    conn = get_db_connection()
    if not conn:
        print(f"{Colors.FAIL}❌ Cannot connect to database{Colors.ENDC}")
        return
    
    try:
        print(f"\n{Colors.OKBLUE}♻️  Optimizing database...{Colors.ENDC}")
        
        cursor = conn.cursor()
        
        # VACUUM - reclaim space
        print(f"  🔄 Running VACUUM...")
        cursor.execute("VACUUM")
        
        # ANALYZE - update statistics
        print(f"  📊 Running ANALYZE...")
        cursor.execute("ANALYZE")
        
        # REINDEX - rebuild indexes
        print(f"  🔨 Rebuilding indexes...")
        cursor.execute("REINDEX")
        
        conn.commit()
        conn.close()
        
        # Show new size
        new_size = os.path.getsize(DB_PATH)
        saved = current_size - new_size
        
        print(f"\n{Colors.OKGREEN}✅ Optimization complete!{Colors.ENDC}")
        print(f"  📊 New size: {get_file_size_bytes(new_size)}")
        
        if saved > 0:
            print(f"  💾 Space saved: {get_file_size_bytes(saved)}")
        else:
            print(f"  ℹ️  No space reclaimed (database already optimized)")
        
        log_event(f"Database optimized: {saved} bytes saved", "INFO")
        
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Optimization error: {e}{Colors.ENDC}")
        log_event(f"Database optimization error: {e}", "ERROR")
        if conn:
            conn.close()

# ============================================================================
# WEB DASHBOARD (Enhanced for Termux)
# ============================================================================

if FLASK_AVAILABLE:
    DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Frankenstein AV - Termux Edition</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            min-height: 100vh;
            padding: 10px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header { text-align: center; padding: 20px 0; }
        h1 { 
            font-size: 2em; 
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            margin-bottom: 5px;
        }
        .subtitle {
            font-size: 0.9em;
            opacity: 0.9;
            margin-bottom: 10px;
        }
        .status-badge {
            display: inline-block;
            padding: 5px 15px;
            background: rgba(255,255,255,0.2);
            border-radius: 20px;
            font-size: 0.85em;
            margin: 5px;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        .card:hover {
            transform: translateY(-5px);
        }
        .card-title { 
            font-size: 1.2em; 
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .card-value { 
            font-size: 2.5em; 
            font-weight: bold; 
            margin: 10px 0;
            color: #fff;
        }
        .card-subtitle {
            font-size: 0.9em;
            opacity: 0.8;
        }
        .threat-list { 
            max-height: 400px; 
            overflow-y: auto; 
            margin-top: 15px;
        }
        .threat-item {
            background: rgba(255,255,255,0.1);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 3px solid #ff4444;
            transition: background 0.3s ease;
        }
        .threat-item:hover {
            background: rgba(255,255,255,0.15);
        }
        .threat-file {
            font-weight: bold;
            margin-bottom: 5px;
            word-break: break-all;
        }
        .threat-name {
            font-size: 0.9em;
            opacity: 0.9;
        }
        .threat-time {
            font-size: 0.8em;
            opacity: 0.7;
            margin-top: 5px;
        }
        .no-threats {
            text-align: center;
            padding: 40px 20px;
            opacity: 0.6;
        }
        .refresh-indicator {
            position: fixed;
            top: 10px;
            right: 10px;
            padding: 8px 15px;
            background: rgba(255,255,255,0.2);
            border-radius: 20px;
            font-size: 0.8em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .pulse {
            width: 8px;
            height: 8px;
            background: #4CAF50;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-top: 10px;
        }
        .stat-item {
            background: rgba(255,255,255,0.05);
            padding: 10px;
            border-radius: 8px;
        }
        .stat-label {
            font-size: 0.8em;
            opacity: 0.7;
        }
        .stat-value {
            font-size: 1.5em;
            font-weight: bold;
            margin-top: 5px;
        }
        /* Mobile responsive */
        @media (max-width: 768px) {
            h1 { font-size: 1.5em; }
            .card-value { font-size: 2em; }
            .dashboard { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="refresh-indicator">
        <div class="pulse"></div>
        <span>Live</span>
    </div>
    
    <div class="container">
        <header>
            <h1>🛡️ Frankenstein AV - Termux Edition</h1>
            <div class="subtitle">Real-time Mobile Security Dashboard</div>
            <div>
                <span class="status-badge" id="device-status">📱 Android/Termux</span>
                <span class="status-badge" id="root-status">🔒 Non-rooted</span>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="card">
                <div class="card-title">📊 Malware Database</div>
                <div class="card-value" id="total-hashes">-</div>
                <div class="card-subtitle">Known Signatures</div>
            </div>
            
            <div class="card">
                <div class="card-title">🔴 Real-time Monitor</div>
                <div class="card-value" id="files-scanned">-</div>
                <div class="card-subtitle">Files Scanned</div>
                <div class="stats-grid" style="margin-top: 15px;">
                    <div class="stat-item">
                        <div class="stat-label">Threats</div>
                        <div class="stat-value" id="threats-found" style="color: #ff4444;">-</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Uptime</div>
                        <div class="stat-value" id="uptime" style="font-size: 1em;">-</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title">🔒 Quarantine</div>
                <div class="card-value" id="quarantine-count">-</div>
                <div class="card-subtitle">Isolated Threats</div>
            </div>
            
            <div class="card">
                <div class="card-title">📱 System Info</div>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-label">DB Size</div>
                        <div class="stat-value" id="db-size" style="font-size: 1em;">-</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Last Update</div>
                        <div class="stat-value" id="last-update" style="font-size: 0.8em;">-</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card" style="margin-top: 20px;">
            <div class="card-title">🚨 Recent Threats</div>
            <div class="threat-list" id="threat-list">
                <div class="no-threats">
                    <div style="font-size: 3em; margin-bottom: 10px;">✅</div>
                    <div>No threats detected</div>
                    <div style="font-size: 0.8em; margin-top: 5px;">Your system is clean</div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }
        
        function formatUptime(seconds) {
            if (!seconds) return '-';
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            if (hours > 0) return `${hours}h ${minutes}m`;
            return `${minutes}m`;
        }
        
        function formatTime(isoString) {
            if (!isoString) return 'Never';
            const date = new Date(isoString);
            const now = new Date();
            const diff = Math.floor((now - date) / 1000);
            
            if (diff < 60) return 'Just now';
            if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
            if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
            return `${Math.floor(diff / 86400)}d ago`;
        }
        
        function updateDashboard() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    // Update main stats
                    document.getElementById('total-hashes').textContent = 
                        (data.database.total || 0).toLocaleString();
                    document.getElementById('files-scanned').textContent = 
                        (data.realtime.files_scanned || 0).toLocaleString();
                    document.getElementById('threats-found').textContent = 
                        (data.realtime.threats_found || 0).toLocaleString();
                    document.getElementById('quarantine-count').textContent = 
                        (data.quarantine.count || 0).toLocaleString();
                    
                    // Update system info
                    document.getElementById('db-size').textContent = 
                        formatBytes(data.system.db_size || 0);
                    document.getElementById('last-update').textContent = 
                        formatTime(data.system.last_update);
                    
                    // Update root status
                    document.getElementById('root-status').textContent = 
                        data.system.is_rooted ? '🔓 Rooted' : '🔒 Non-rooted';
                    
                    // Calculate uptime
                    if (data.realtime.started_at) {
                        const startTime = new Date(data.realtime.started_at);
                        const uptime = Math.floor((new Date() - startTime) / 1000);
                        document.getElementById('uptime').textContent = formatUptime(uptime);
                    }
                    
                    // Update threat list
                    const list = document.getElementById('threat-list');
                    if (data.threats && data.threats.length > 0) {
                        list.innerHTML = data.threats.map(t => {
                            const fileName = t.file.split('/').pop();
                            return `
                                <div class="threat-item">
                                    <div class="threat-file">📁 ${fileName}</div>
                                    <div class="threat-name">🚨 ${t.threat || t.detections || 'Unknown Threat'}</div>
                                    ${t.timestamp ? `<div class="threat-time">⏰ ${formatTime(t.timestamp)}</div>` : ''}
                                </div>
                            `;
                        }).join('');
                    } else {
                        list.innerHTML = `
                            <div class="no-threats">
                                <div style="font-size: 3em; margin-bottom: 10px;">✅</div>
                                <div>No threats detected</div>
                                <div style="font-size: 0.8em; margin-top: 5px;">Your system is clean</div>
                            </div>
                        `;
                    }
                })
                .catch(err => {
                    console.error('Update failed:', err);
                });
        }
        
        // Initial update
        updateDashboard();
        
        // Update every 3 seconds
        setInterval(updateDashboard, 3000);
    </script>
</body>
</html>
"""
    
    @app.route('/')
    def dashboard():
        return render_template_string(DASHBOARD_HTML)
    
    @app.route('/api/stats')
    def api_stats():
        # Database stats
        conn = get_db_connection()
        db_stats = {'total': 0}
        db_size = 0
        
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM hashes")
                db_stats['total'] = cursor.fetchone()[0]
                conn.close()
            except:
                pass
        
        if os.path.exists(DB_PATH):
            db_size = os.path.getsize(DB_PATH)
        
        # Quarantine count
        quarantine_count = 0
        if os.path.exists(QUARANTINE_DIR):
            quarantine_count = len([f for f in os.listdir(QUARANTINE_DIR) if not f.endswith('.meta')])
        
        # Get last update time
        last_update = None
        if os.path.exists(UPDATE_CONFIG_FILE):
            try:
                with open(UPDATE_CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    last_update = config.get('last_update')
            except:
                pass
        
        return jsonify({
            'database': db_stats,
            'realtime': REALTIME_STATS,
            'quarantine': {'count': quarantine_count},
            'threats': REALTIME_THREATS[-20:],
            'system': {
                'db_size': db_size,
                'last_update': last_update,
                'is_rooted': IS_ROOTED
            }
        })
    
    def get_local_ip():
        """Get local IP address for network access."""
        try:
            # Create a socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "localhost"
    
    def open_browser(url, delay=2):
        """Open browser with delay."""
        import time
        time.sleep(delay)
        try:
            # For Termux, use termux-open-url if available
            if IS_TERMUX:
                try:
                    subprocess.run(['termux-open-url', url], check=True)
                    return
                except:
                    pass
            
            # Fallback to Python's webbrowser
            webbrowser.open(url)
        except Exception as e:
            print(f"{Colors.WARNING}Could not auto-open browser: {e}{Colors.ENDC}")
    
    def start_web_dashboard(port: int = 5000, auto_open: bool = True):
        """Start web dashboard with auto browser open."""
        print(f"\n{Colors.BOLD}🌐 Web Dashboard Starting...{Colors.ENDC}\n")
        
        # Get local IP
        local_ip = get_local_ip()
        
        print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}🌐 Web Dashboard URLs:{Colors.ENDC}\n")
        print(f"  📱 Local Access:   http://localhost:{port}")
        print(f"  🌐 Network Access: http://{local_ip}:{port}")
        print(f"\n{Colors.OKCYAN}💡 Access from other devices on same WiFi using the network URL{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}\n")
        
        print(f"{Colors.WARNING}⚠️  Press Ctrl+C to stop the dashboard{Colors.ENDC}\n")
        
        # Auto-open browser
        if auto_open:
            print(f"{Colors.OKBLUE}🚀 Opening browser...{Colors.ENDC}")
            import threading
            url = f"http://localhost:{port}"
            threading.Thread(target=open_browser, args=(url,), daemon=True).start()
        
        try:
            # Suppress Flask development server warning
            import logging
            log = logging.getLogger('werkzeug')
            log.setLevel(logging.ERROR)
            
            app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}⏹️  Dashboard stopped{Colors.ENDC}")
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"{Colors.FAIL}❌ Port {port} is already in use!{Colors.ENDC}")
                print(f"{Colors.OKCYAN}💡 Try a different port or stop the existing service{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}❌ Error: {e}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}❌ Dashboard error: {e}{Colors.ENDC}")

else:
    def start_web_dashboard(port: int = 5000, auto_open: bool = True):
        print(f"{Colors.FAIL}❌ Flask not installed{Colors.ENDC}")
        print(f"{Colors.WARNING}Install with: pip install flask{Colors.ENDC}")
        
def import_hashes_from_file(filepath: str):
    """Import hashes from file."""
    sanitized = sanitize_path(filepath)
    if not sanitized:
        print(f"{Colors.FAIL}❌ File not found{Colors.ENDC}")
        return
    
    try:
        print(f"\n{Colors.OKBLUE}📥 Importing...{Colors.ENDC}")
        
        with open(sanitized, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        hash_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b')
        
        imported = 0
        duplicates = 0
        
        for line in tqdm(lines, desc="Processing", unit="line"):
            line = line.split('#')[0].strip()
            if not line:
                continue
            
            matches = hash_pattern.findall(line)
            for hash_val in matches:
                if not validate_hash(hash_val):
                    continue
                
                if db_check_hash(hash_val):
                    duplicates += 1
                else:
                    if db_add_hash(hash_val, "Imported", "File"):
                        imported += 1
        
        print(f"\n{Colors.OKGREEN}✅ Complete!{Colors.ENDC}")
        print(f"  📥 Imported: {imported}")
        print(f"  🔄 Duplicates: {duplicates}")
    
    except Exception as e:
        print(f"{Colors.FAIL}❌ Error: {e}{Colors.ENDC}")

# ============================================================================
# PATCH 4: VT AUTO-NAME HASHES (from Windows version)
# ============================================================================
def vt_auto_name_hashes(max_workers: int = 4):
    """Auto-name hashes using VirusTotal."""
    if not VT_API_KEY:
        print(f"{Colors.FAIL}❌ VT API Key required{Colors.ENDC}")
        return
    
    processed = set()
    if os.path.exists(RESUME_FILE):
        try:
            with open(RESUME_FILE, 'r') as f:
                processed = set(json.load(f))
        except:
            pass
    
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cursor = conn.cursor()
        # IMPROVED: Now includes generic names from all sources
        cursor.execute("""
            SELECT hash FROM hashes 
            WHERE name IN (
                'Imported Hash', 
                'Downloaded Hash', 
                'Unknown',
                'MalwareBazaar Detected Threat',
                'Downloaded from MalwareBazaar',
                'Downloaded from MalShare',
                'Downloaded from Hybrid Analysis',
                'Downloaded from Custom',
                'Imported malware hash',
                'Imported Github hash',
                'Downloaded from VirusTotal',
                'Imported VT hash',
                'Imported',
                'Custom'
            )
            OR name LIKE 'Downloaded from%'
            OR name LIKE 'Imported%'
        """)
        rows = cursor.fetchall()
        conn.close()
    except Exception as e:
        print(f"{Colors.FAIL}❌ Error: {e}{Colors.ENDC}")
        return
    
    all_hashes = [r[0] for r in rows if r[0] not in processed]
    total = len(all_hashes)
    
    if total == 0:
        print(f"{Colors.OKGREEN}✅ All hashes already named{Colors.ENDC}")
        return
    
    print(f"\n{Colors.BOLD}🌐 VT Auto-Naming Tool{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}📊 Hashes needing names: {total:,}{Colors.ENDC}")
    print(f"{Colors.WARNING}⚠️  Estimated time: ~{total//4} minutes ({total//240:.1f} hours){Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'='*70}{Colors.ENDC}\n")
    
    # Offer batch processing
    print(f"{Colors.OKGREEN}Options:{Colors.ENDC}")
    print(f"  1. Process ALL {total:,} hashes (may take {total//240:.1f} hours)")
    print(f"  2. Process first 100 hashes only (~25 minutes)")
    print(f"  3. Process first 500 hashes only (~2 hours)")
    print(f"  4. Process first 1000 hashes only (~4 hours)")
    print(f"  5. Custom amount")
    print(f"  0. Cancel")
    
    batch_choice = input(f"\n{Colors.OKCYAN}Choice: {Colors.ENDC}").strip()
    
    if batch_choice == '0':
        print(f"{Colors.WARNING}Cancelled{Colors.ENDC}")
        return
    elif batch_choice == '1':
        batch_size = total
    elif batch_choice == '2':
        batch_size = min(100, total)
    elif batch_choice == '3':
        batch_size = min(500, total)
    elif batch_choice == '4':
        batch_size = min(1000, total)
    elif batch_choice == '5':
        try:
            batch_size = int(input(f"{Colors.OKCYAN}How many hashes? {Colors.ENDC}"))
            batch_size = min(batch_size, total)
        except:
            print(f"{Colors.FAIL}Invalid number, using 100{Colors.ENDC}")
            batch_size = 100
    else:
        print(f"{Colors.WARNING}Invalid choice, cancelled{Colors.ENDC}")
        return
    
    all_hashes = all_hashes[:batch_size]
    
    print(f"\n{Colors.OKGREEN}Processing {len(all_hashes):,} hashes...{Colors.ENDC}")
    print(f"{Colors.WARNING}⚠️  Press Ctrl+C to stop gracefully (progress will be saved){Colors.ENDC}\n")
    
    headers = {"x-apikey": VT_API_KEY}
    stop_requested = threading.Event()
    
    def query_and_update(h):
        # Check if stop was requested
        if stop_requested.is_set():
            return h, None
        
        try:
            rate_limit_vt()
            
            # Check again after waiting
            if stop_requested.is_set():
                return h, None
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{h}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
                names = [info.get('result') for info in results.values() 
                        if info.get('category') == 'malicious' and info.get('result')]
                
                if names:
                    final_name = Counter(names).most_common(1)[0][0]
                    conn2 = get_db_connection()
                    if conn2:
                        try:
                            cursor2 = conn2.cursor()
                            cursor2.execute("UPDATE hashes SET name = ? WHERE hash = ?", (final_name, h))
                            conn2.commit()
                            conn2.close()
                            return h, final_name
                        except:
                            if conn2:
                                conn2.close()
            return h, None
        except Exception as e:
            return h, None
    
    updated = 0
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(query_and_update, h): h for h in all_hashes}
            
            with tqdm(total=len(futures), desc="VT Naming", unit="hash") as pbar:
                for future in as_completed(futures):
                    try:
                        h, name = future.result()
                        processed.add(h)
                        
                        # Save progress every 10 hashes
                        if len(processed) % 10 == 0:
                            try:
                                with open(RESUME_FILE, 'w') as f:
                                    json.dump(list(processed), f)
                            except:
                                pass
                        
                        if name:
                            updated += 1
                            pbar.set_postfix({'updated': updated, 'skipped': len(processed)-updated})
                        
                        pbar.update(1)
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        pbar.update(1)
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}⏹️  Interrupt detected! Stopping gracefully...{Colors.ENDC}")
        stop_requested.set()
        
        # Wait a moment for threads to finish current tasks
        print(f"{Colors.OKCYAN}⏳ Waiting for current requests to complete...{Colors.ENDC}")
        time.sleep(2)
        
        # Save progress
        try:
            with open(RESUME_FILE, 'w') as f:
                json.dump(list(processed), f)
            print(f"{Colors.OKGREEN}✅ Progress saved to: {RESUME_FILE}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}⚠️  Could not save progress: {e}{Colors.ENDC}")
        
        print(f"\n{Colors.OKBLUE}📊 Progress before stop:{Colors.ENDC}")
        print(f"  • Processed: {len(processed):,}/{len(all_hashes):,}")
        print(f"  • Updated: {updated:,}")
        print(f"  • Remaining: {len(all_hashes) - len(processed):,}")
        print(f"\n{Colors.OKCYAN}💡 Tip: Run this again to continue from where you left off{Colors.ENDC}")
        return
    
    # Clean up resume file on completion
    if os.path.exists(RESUME_FILE):
        try:
            os.remove(RESUME_FILE)
        except:
            pass
    
    print(f"\n{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}✅ Auto-naming Complete!{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
    print(f"  📊 Processed: {len(processed):,}/{len(all_hashes):,}")
    print(f"  ✅ Updated: {updated:,}")
    print(f"  ⏭️  Skipped: {len(processed) - updated:,}")
    
    if len(all_hashes) < total:
        remaining = total - len(all_hashes)
        print(f"\n{Colors.WARNING}⚠️  {remaining:,} hashes still need naming{Colors.ENDC}")
        print(f"{Colors.OKCYAN}💡 Run this tool again to continue{Colors.ENDC}")
    
    print(f"\n{Colors.OKCYAN}💡 Tip: Check 'Database Stats' to see updated names{Colors.ENDC}")
    log_event(f"VT auto-naming: {updated}/{len(all_hashes)} updated", "INFO")
    
# ============================================================================
# PATCH 5: DOWNLOAD ONLINE HASHES
# ============================================================================

def download_online_hashes():
    """Download hashes from online sources."""
    print(f"\n{Colors.BOLD}🌐 Download Hashes{Colors.ENDC}\n")
    print(f"  1. 🔥 MalwareBazaar (Recent)")
    print(f"  2. 🔗 MalShare (Requires API Key)")
    print(f"  3. 🔬 Hybrid Analysis (Requires API Key)")
    print(f"  4. 🌐 Custom URL")
    print(f"  0. 🔙 Back")
    
    choice = input(f"\n{Colors.OKCYAN}Choice: {Colors.ENDC}").strip()
    
    if choice == '1':
        download_from_url("https://bazaar.abuse.ch/export/txt/sha256/recent/", "MalwareBazaar")
    elif choice == '2':
        api_key = MALSHARE_API_KEY or input(f"{Colors.OKCYAN}MalShare API Key: {Colors.ENDC}").strip()
        if api_key:
            url = f"https://malshare.com/api.php?api_key={api_key}&action=getlistraw"
            download_from_url(url, "MalShare")
        else:
            print(f"{Colors.WARNING}API Key required{Colors.ENDC}")
    elif choice == '3':
        api_key = HYBRID_API_KEY or input(f"{Colors.OKCYAN}Hybrid Analysis API Key: {Colors.ENDC}").strip()
        if api_key:
            headers = {"api-key": api_key, "user-agent": "Frankenstein-AV"}
            download_from_url("https://www.hybrid-analysis.com/feed?json", "Hybrid", headers)
        else:
            print(f"{Colors.WARNING}API Key required{Colors.ENDC}")
    elif choice == '4':
        url = input(f"{Colors.OKCYAN}Hash list URL: {Colors.ENDC}").strip()
        if validate_url(url):
            download_from_url(url, "Custom")
        else:
            print(f"{Colors.FAIL}Invalid URL{Colors.ENDC}")


@retry_on_failure(retries=3, delay=5)
def download_from_url(url: str, source: str, headers: Optional[Dict] = None):
    """Download and import hashes."""
    print(f"\n{Colors.OKBLUE}🌐 Downloading from {source}...{Colors.ENDC}")
    
    try:
        response = requests.get(url, timeout=30, headers=headers or {})
        response.raise_for_status()
        
        hash_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b')
        hashes = hash_pattern.findall(response.text)
        unique_hashes = list(set(h.lower() for h in hashes if validate_hash(h)))
        
        if not unique_hashes:
            print(f"{Colors.WARNING}⚠️  No hashes found{Colors.ENDC}")
            return
        
        print(f"{Colors.OKGREEN}✅ Found {len(unique_hashes)} hashes{Colors.ENDC}")
        
        imported = 0
        duplicates = 0
        
        for h in tqdm(unique_hashes, desc="Importing", unit="hash"):
            if not db_check_hash(h):
                if db_add_hash(h, f"Downloaded from {source}", source):
                    imported += 1
            else:
                duplicates += 1
        
        print(f"\n{Colors.OKGREEN}✅ Imported {imported} new hashes{Colors.ENDC}")
        print(f"  🔄 Duplicates skipped: {duplicates}")
        log_event(f"Downloaded hashes from {source}: {imported} new, {duplicates} duplicates", "INFO")
    
    except Exception as e:
        print(f"{Colors.FAIL}❌ Error: {e}{Colors.ENDC}")
        log_event(f"Download error from {source}: {e}", "ERROR")
        raise

# ============================================================================
# PATCH 6: AUTO UPDATES CONFIGURATION
# ============================================================================

def configure_auto_updates():
    """Configure auto-updates."""
    print(f"\n{Colors.BOLD}⏰ Auto-Update Configuration{Colors.ENDC}\n")
    
    config = {"enabled": False, "frequency": "daily", "last_update": None}
    
    if os.path.exists(UPDATE_CONFIG_FILE):
        try:
            with open(UPDATE_CONFIG_FILE, 'r') as f:
                config.update(json.load(f))
        except:
            pass
    
    print(f"{Colors.OKGREEN}Current Settings:{Colors.ENDC}")
    print(f"  • Status: {'✅ Enabled' if config['enabled'] else '❌ Disabled'}")
    print(f"  • Frequency: {config['frequency']}")
    print(f"  • Last Update: {config['last_update'] or 'Never'}\n")
    
    print(f"{Colors.OKCYAN}Options:{Colors.ENDC}")
    print(f"  1. ✅ Enable Auto-Updates")
    print(f"  2. ❌ Disable Auto-Updates")
    print(f"  3. 🔄 Change Frequency")
    print(f"  4. ⚡ Update Now")
    print(f"  0. 🔙 Back")
    
    choice = input(f"\n{Colors.OKCYAN}Choice: {Colors.ENDC}").strip()
    
    if choice == '1':
        config['enabled'] = True
        print(f"{Colors.OKGREEN}✅ Auto-updates enabled{Colors.ENDC}")
    elif choice == '2':
        config['enabled'] = False
        print(f"{Colors.WARNING}❌ Auto-updates disabled{Colors.ENDC}")
    elif choice == '3':
        print(f"\n{Colors.OKCYAN}Select frequency:{Colors.ENDC}")
        print(f"  1. Daily")
        print(f"  2. Weekly")
        freq_choice = input(f"{Colors.OKCYAN}Choice: {Colors.ENDC}").strip()
        if freq_choice == '1':
            config['frequency'] = 'daily'
            print(f"{Colors.OKGREEN}✅ Set to daily{Colors.ENDC}")
        elif freq_choice == '2':
            config['frequency'] = 'weekly'
            print(f"{Colors.OKGREEN}✅ Set to weekly{Colors.ENDC}")
    elif choice == '4':
        update_malware_database()
        config['last_update'] = datetime.now().isoformat()
    
    try:
        with open(UPDATE_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error saving config: {e}{Colors.ENDC}")


def check_auto_updates():
    """Check and run auto-updates if needed."""
    if not os.path.exists(UPDATE_CONFIG_FILE):
        return
    
    try:
        with open(UPDATE_CONFIG_FILE, 'r') as f:
            config = json.load(f)
        
        if not config.get('enabled'):
            return
        
        last_update = config.get('last_update')
        if not last_update:
            return
        
        last_dt = datetime.fromisoformat(last_update)
        days_diff = (datetime.now() - last_dt).days
        
        should_update = False
        if config.get('frequency') == 'daily' and days_diff >= 1:
            should_update = True
        elif config.get('frequency') == 'weekly' and days_diff >= 7:
            should_update = True
        
        if should_update:
            print(f"{Colors.OKBLUE}🔄 Running scheduled auto-update...{Colors.ENDC}")
            update_malware_database()
            config['last_update'] = datetime.now().isoformat()
            with open(UPDATE_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
    except:
        pass
                
# ============================================================================
# APK SCANNER (NEW ANDROID FEATURE)
# ============================================================================

def scan_apk_directory():
    """Scan Android APK directory for malicious apps."""
    print(f"\n{Colors.BOLD}📱 APK Scanner{Colors.ENDC}\n")
    
    # Common APK locations on Android
    apk_paths = [
        "/data/app",  # Installed apps (requires root)
        "/system/app",  # System apps (requires root)
        "/sdcard/Download",  # Downloads
        os.path.expanduser("~/storage/downloads"),  # Termux accessible downloads
    ]
    
    print(f"{Colors.OKCYAN}Scan locations:{Colors.ENDC}")
    for idx, path in enumerate(apk_paths, 1):
        accessible = "✅" if os.path.exists(path) and os.access(path, os.R_OK) else "❌"
        print(f"  {idx}. {accessible} {path}")
    
    choice = input(f"\n{Colors.OKCYAN}Choose location (1-{len(apk_paths)}) or custom path: {Colors.ENDC}").strip()
    
    try:
        if choice.isdigit() and 1 <= int(choice) <= len(apk_paths):
            scan_path = apk_paths[int(choice) - 1]
        else:
            scan_path = choice
        
        if not os.path.exists(scan_path):
            print(f"{Colors.FAIL}❌ Path not accessible{Colors.ENDC}")
            return
        
        print(f"\n{Colors.OKBLUE}🔍 Scanning APKs in: {scan_path}{Colors.ENDC}")
        
        apk_files = []
        for root, _, files in os.walk(scan_path):
            for filename in files:
                if filename.endswith('.apk'):
                    apk_files.append(os.path.join(root, filename))
        
        if not apk_files:
            print(f"{Colors.WARNING}⚠️  No APK files found{Colors.ENDC}")
            return
        
        print(f"{Colors.OKGREEN}Found {len(apk_files)} APK files{Colors.ENDC}\n")
        
        threats_found = 0
        for apk_file in tqdm(apk_files, desc="Scanning APKs", unit="apk"):
            apk_hash = calculate_file_hash(apk_file)
            if apk_hash:
                found, name, source = check_hash_in_databases(apk_hash)
                if found:
                    threats_found += 1
                    print(f"\n{Colors.FAIL}🚨 THREAT: {os.path.basename(apk_file)}{Colors.ENDC}")
                    print(f"   {name}")
                    log_event(f"Malicious APK: {apk_file} - {name}", "ALERT")
        
        print(f"\n{Colors.OKGREEN}📊 APK Scan Complete!{Colors.ENDC}")
        print(f"  📱 Scanned: {len(apk_files)}")
        print(f"  🚨 Threats: {threats_found}")
        
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")

# ============================================================================
# SYSTEM PERMISSIONS CHECKER (NEW ANDROID FEATURE)
# ============================================================================

def check_android_permissions():
    """Check Termux permissions and suggest improvements."""
    print(f"\n{Colors.BOLD}📋 Termux Permissions Check{Colors.ENDC}\n")
    
    permissions = {
        "Storage Access": os.path.exists(os.path.expanduser("~/storage")),
        "Root Access": IS_ROOTED,
        "Network Access": True,  # Termux always has network
    }
    
    # Check accessible paths
    important_paths = {
        "/sdcard": "External Storage",
        "/data/data/com.termux": "Termux Home",
        "/system": "System Files (Root)",
        "/data/app": "Installed Apps (Root)",
    }
    
    print(f"{Colors.OKCYAN}📱 Permission Status:{Colors.ENDC}")
    for perm, status in permissions.items():
        icon = "✅" if status else "❌"
        print(f"  {icon} {perm}")
    
    print(f"\n{Colors.OKCYAN}📂 Path Accessibility:{Colors.ENDC}")
    for path, desc in important_paths.items():
        if os.path.exists(path):
            readable = os.access(path, os.R_OK)
            writable = os.access(path, os.W_OK)
            status = "✅ R" if readable else "❌"
            status += "/W" if writable else ""
            print(f"  {status} {desc}: {path}")
        else:
            print(f"  ❌ {desc}: {path} (not accessible)")
    
    if not permissions["Storage Access"]:
        print(f"\n{Colors.WARNING}💡 To enable storage access:{Colors.ENDC}")
        print(f"{Colors.OKCYAN}   termux-setup-storage{Colors.ENDC}")
    
    if not permissions["Root Access"]:
        print(f"\n{Colors.WARNING}💡 Root access enables:{Colors.ENDC}")
        print(f"   • Firewall (iptables)")
        print(f"   • System-wide scanning")
        print(f"   • APK scanning in /system")

# ============================================================================
# NETWORK MONITOR (NEW ANDROID FEATURE)
# ============================================================================

def monitor_network_connections():
    """Monitor active network connections."""
    print(f"\n{Colors.BOLD}🌐 Network Connection Monitor{Colors.ENDC}\n")
    
    try:
        # Try to read /proc/net/tcp for active connections
        if os.path.exists("/proc/net/tcp"):
            print(f"{Colors.OKBLUE}Active TCP Connections:{Colors.ENDC}\n")
            
            with open("/proc/net/tcp", "r") as f:
                lines = f.readlines()[1:]  # Skip header
            
            connections = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3]
                    
                    # Parse hex addresses
                    def parse_addr(addr_hex):
                        try:
                            addr, port = addr_hex.split(":")
                            # Convert hex to IP
                            ip_parts = [str(int(addr[i:i+2], 16)) for i in range(6, -1, -2)]
                            ip = ".".join(ip_parts)
                            port_dec = int(port, 16)
                            return f"{ip}:{port_dec}"
                        except:
                            return addr_hex
                    
                    local = parse_addr(local_addr)
                    remote = parse_addr(remote_addr)
                    
                    connections.append((local, remote, state))
            
            print(f"{Colors.OKGREEN}Found {len(connections)} active connections{Colors.ENDC}\n")
            
            for idx, (local, remote, state) in enumerate(connections[:20], 1):
                print(f"{idx}. {local} → {remote} (State: {state})")
            
            if len(connections) > 20:
                print(f"\n{Colors.WARNING}... and {len(connections) - 20} more{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}⚠️  Cannot access /proc/net/tcp{Colors.ENDC}")
    
    except Exception as e:
        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")

def main_menu():
    """Main interactive menu for Termux."""
    while True:
        print_banner()
        print(f"{Colors.BOLD}🎯 MAIN MENU{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{'='*70}{Colors.ENDC}\n")
               
        print(f"{Colors.HEADER}📱 MOBILE SCANNING:{Colors.ENDC}")
        print(f"  1. ⚡ Quick Scan (Easy Mode)")  # NEW!
        print(f"  2. 🔍 Scan Single File")
        print(f"  3. 🌐 Scan with VirusTotal")
        print(f"  4. 📁 Scan Directory (Advanced)")
        print(f"  5. 📱 Scan APK Files")
        
        print(f"\n{Colors.HEADER}🛡️  FILE INTEGRITY:{Colors.ENDC}")
        print(f"  6. 🔧 Initialize FIM Baseline")
        print(f"  7. 🔍 Check File Integrity")
        
        print(f"\n{Colors.HEADER}🌐 NETWORK SECURITY:{Colors.ENDC}")
        print(f"  8. 🌐 Check URL Reputation")
        print(f"  9. 🌐 Check IP Reputation")
        print(f"  10. 🔥 Firewall Management (Root)")
        print(f"  11. 🌐 Monitor Network Connections")
        
        print(f"\n{Colors.HEADER}🔄 DATABASE:{Colors.ENDC}")
        print(f"  12. 📥 Update Malware Database")
        print(f"  13. 🔧 Manual Hash Management")
        print(f"  14. 📊 Database Statistics")
        print(f"  22. 🌐 Download Online Hashes")     # NEW!
        print(f"  23. 🤖 VT Auto-Name Hashes")        # NEW!
        print(f"  24. ⏰ Configure Auto-Updates")     # NEW!
        print(f"  20. 📦 Migrate JSON → SQLite")
        print(f"  21. 📤 Export SQLite → JSON")
        print(f"  25. ♻️  Optimize Database (VACUUM)") # NEW!
        
        print(f"\n{Colors.HEADER}⚙️  SYSTEM:{Colors.ENDC}")
        print(f"  15. 🔒 Quarantine Management")
        print(f"  16. 📜 View Logs")
        print(f"  17. 📄 View Reports")
        print(f"  18. 📋 Check Permissions")
        print(f"  19. 💻 System Information")
        print(f"  26. 🌐 Web Dashboard")
         
        print(f"\n{Colors.FAIL}  0. 🚪 Exit{Colors.ENDC}")
        print(f"\n{Colors.OKCYAN}{'='*70}{Colors.ENDC}")
        
        choice = input(f"{Colors.OKCYAN}👉 Choice: {Colors.ENDC}").strip()
        
        try:
            if choice == '1':
                quick_scan_menu()  # NEW!
            elif choice == '2':
                filepath = input(f"{Colors.OKCYAN}File path: {Colors.ENDC}").strip()
                scan_file_local_hash(filepath)
            elif choice == '3':
                filepath = input(f"{Colors.OKCYAN}File path: {Colors.ENDC}").strip()
                scan_file_virustotal(filepath)
            elif choice == '4':
                directory = input(f"{Colors.OKCYAN}Directory: {Colors.ENDC}").strip()
                recursive = input(f"{Colors.OKCYAN}Recursive? (Y/n): {Colors.ENDC}").strip().lower() != 'n'
                scan_directory(directory, recursive)
            elif choice == '5':
                scan_apk_directory()
            
            elif choice == '6':
                target = input(f"{Colors.OKCYAN}Directory to monitor: {Colors.ENDC}").strip()
                file_integrity_monitor_init(target)
            
            elif choice == '7':
                target = input(f"{Colors.OKCYAN}Directory to check: {Colors.ENDC}").strip()
                file_integrity_monitor_check(target)
            
            elif choice == '8':
                url = input(f"{Colors.OKCYAN}URL: {Colors.ENDC}").strip()
                check_url_reputation(url)
            
            elif choice == '9':
                ip = input(f"{Colors.OKCYAN}IP: {Colors.ENDC}").strip()
                check_ip_reputation(ip)
            
            elif choice == '10':
                manage_firewall_iptables()
            
            elif choice == '11':
                monitor_network_connections()
            
            elif choice == '12':
                update_malware_database()
            
            elif choice == '13':
                manual_hash_management()
            
            elif choice == '14':
                conn = get_db_connection()
                if conn:
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT COUNT(*) FROM hashes")
                        total = cursor.fetchone()[0]
                        
                        cursor.execute("SELECT COUNT(*) FROM hashes WHERE LENGTH(hash)=32")
                        md5 = cursor.fetchone()[0]
                        
                        cursor.execute("SELECT COUNT(*) FROM hashes WHERE LENGTH(hash)=64")
                        sha256 = cursor.fetchone()[0]
                        
                        cursor.execute("SELECT source, COUNT(*) FROM hashes GROUP BY source")
                        sources = cursor.fetchall()
                        
                        print(f"\n{Colors.OKCYAN}📊 Database Statistics:{Colors.ENDC}")
                        print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}")
                        print(f"  • Total hashes: {Colors.OKGREEN}{total}{Colors.ENDC}")
                        print(f"  • MD5: {md5}")
                        print(f"  • SHA256: {sha256}")
                        print(f"\n{Colors.BOLD}Sources:{Colors.ENDC}")
                        for source, count in sources:
                            print(f"  • {source}: {count}")
                        print(f"{Colors.OKBLUE}{'='*70}{Colors.ENDC}")
                        
                        conn.close()
                    except Exception as e:
                        print(f"{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")
            
            elif choice == '15':
                view_quarantine()
            
            elif choice == '16':
                view_logs()
            
            elif choice == '17':
                view_reports()
            
            elif choice == '18':
                check_android_permissions()
            
            elif choice == '19':
                print(f"\n{Colors.BOLD}💻 System Information{Colors.ENDC}")
                print(f"{Colors.OKCYAN}{'='*70}{Colors.ENDC}")
                print(f"  🖥️  OS: Android/Termux")
                print(f"  🏗️  Architecture: {platform.machine()}")
                print(f"  🐍 Python: {platform.python_version()}")
                print(f"  📂 Working Dir: {SCRIPT_DIR}")
                print(f"  📝 Script: {os.path.abspath(__file__)}")
                print(f"\n{Colors.BOLD}Status:{Colors.ENDC}")
                print(f"  🔓 Root: {'✅ Yes' if IS_ROOTED else '❌ No'}")
                print(f"  🔑 VT API: {'✅ Set' if VT_API_KEY else '❌ Not Set'}")
                print(f"  🗄️  SQLite: {'✅ Exists' if os.path.exists(DB_PATH) else '❌ Not Found'}")
                
                # Check database size
                if os.path.exists(DB_PATH):
                    db_size = get_file_size(DB_PATH)
                    print(f"  📊 DB Size: {db_size}")
                
                # Check storage
                try:
                    import shutil
                    total, used, free = shutil.disk_usage(SCRIPT_DIR)
                    print(f"\n{Colors.BOLD}Storage:{Colors.ENDC}")
                    print(f"  💾 Total: {get_file_size_bytes(total)}")
                    print(f"  📊 Used: {get_file_size_bytes(used)}")
                    print(f"  ✅ Free: {get_file_size_bytes(free)}")
                except:
                    pass
                
                print(f"{Colors.OKCYAN}{'='*70}{Colors.ENDC}")
            elif choice == '20':
                migrate_json_to_sqlite()
            elif choice == '21':
                export_sqlite_to_json()
            elif choice == '22':
                download_online_hashes()            
            elif choice == '23':
                vt_auto_name_hashes() 
            elif choice == '24':
                configure_auto_updates()
            elif choice == '25':
                optimize_sqlite() 
            elif choice == '26':
                print(f"\n{Colors.OKCYAN}Web Dashboard Options:{Colors.ENDC}")
                port = input(f"{Colors.OKCYAN}Port (default: 5000): {Colors.ENDC}").strip()
                port = int(port) if port and port.isdigit() else 5000
                
                auto_open = input(f"{Colors.OKCYAN}Auto-open browser? (Y/n): {Colors.ENDC}").strip().lower()
                auto_open = auto_open != 'n'
                
                start_web_dashboard(port, auto_open)       
            elif choice == '0':
                print(f"\n{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
                print(f"{Colors.OKGREEN}👋 Thank you for using Frankenstein AV!{Colors.ENDC}")
                print(f"{Colors.OKGREEN}🔒 Stay secure! 🛡️{Colors.ENDC}")
                print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}\n")
                log_event("Application exited", "INFO")
                break
            
            else:
                print(f"{Colors.WARNING}⚠️  Invalid choice{Colors.ENDC}")
        
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}⚠️  Interrupted{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")
            log_event(f"Menu error: {e}", "ERROR")
        
        input(f"\n{Colors.OKCYAN}⏎ Press Enter...{Colors.ENDC}")
        os.system('clear')

def get_file_size_bytes(size_bytes):
    """Convert bytes to human readable."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

# ============================================================================
# MAIN ENTRY
# ============================================================================

if __name__ == "__main__":
    try:
        setup_directories()
        log_event("Frankenstein AV Termux started", "INFO")
        init_database()
        
        if not VT_API_KEY:
            print(f"\n{Colors.WARNING}⚠️  VT API Key not configured{Colors.ENDC}")
            print(f"Create .env file with: VT_API_KEY=\"your_key\"")
            time.sleep(2)
        
        print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}📱 Termux Antivirus Ready{Colors.ENDC}")
        print(f"{Colors.OKGREEN}📂 Directory: {SCRIPT_DIR}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}\n")
        time.sleep(1)
        
        # Check auto-updates
        check_auto_updates() 
        
        # Start menu
        main_menu()
    
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}⚠️  Interrupted{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.FAIL}⚠️  Error: {e}{Colors.ENDC}")
    finally:
        log_event("Application closed", "INFO")