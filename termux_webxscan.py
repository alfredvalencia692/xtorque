# !/usr/bin/env python3
#!/data/data/com.termux/files/usr/bin/python3
"""
Web XScan Professional v2.1 - Enterprise-Grade Security Scanner
---------------------------------------------------------------

Professional-grade website & IP security scanner with:

- Dual Input: URLs and IP Addresses
- Dual Mode: Console (CLI) and Web (Browser)
- Enterprise features: Rate limiting, logging, validation
- Advanced security checks: SSL, WHOIS, VirusTotal, Headers
- Smart caching and offline detection
- Export capabilities (JSON)
- Historical tracking and analytics

Author: Frank Net Tools
License: MIT
Version: 2.1.0 - NOW WITH IP ADDRESS SUPPORT
"""

# ============================================================================

# IMPORTS & DEPENDENCIES

# ============================================================================

import os
import sys
import time
import json
import socket
import ssl
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import requests
import concurrent.futures
import webbrowser
import threading
import urllib.parse
import re
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from functools import wraps
from collections import defaultdict

# Optional dependencies with graceful fallbacks

try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
    import dns.reversename
except ImportError:
    dns = None

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.style import Style
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

try:
    from flask import Flask, request, render_template_string, jsonify, session
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    Flask = None

def detect_termux():
    """Detect Termux and set appropriate paths"""
    is_termux = os.path.exists('/data/data/com.termux')
    
    if is_termux:
        # Try multiple possible paths
        paths = [
            Path('/sdcard/xscan'),
            Path('/storage/emulated/0/xscan'),
            Path.home() / 'xscan',
        ]
        
        for p in paths:
            try:
                p.mkdir(parents=True, exist_ok=True)
                test = p / '.test'
                test.touch()
                test.unlink()
                return p
            except:
                continue
        
        return Path.home() / '.webxscan'
    
    return Path.home() / '.webxscan'

# Use this instead of hardcoded path
BASE_DIR = detect_termux()
IS_TERMUX = os.path.exists('/data/data/com.termux')

def open_browser_termux(url: str) -> bool:
    """
    Open browser - works on both Termux and desktop
    Returns True if successful
    """
    if IS_TERMUX:
        import subprocess
        
        # Method 1: termux-open-url (best)
        try:
            result = subprocess.run(
                ['termux-open-url', url],
                capture_output=True,
                timeout=3
            )
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Method 2: Android intent (fallback)
        try:
            result = subprocess.run([
                'am', 'start',
                '--user', '0',
                '-a', 'android.intent.action.VIEW',
                '-d', url
            ], capture_output=True, timeout=3)
            
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Method 3: xdg-open (some Termux setups)
        try:
            result = subprocess.run(
                ['xdg-open', url],
                capture_output=True,
                timeout=3
            )
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        return False
    else:
        # Desktop systems
        try:
            import webbrowser
            return webbrowser.open(url)
        except:
            return False

def get_utc_timestamp() -> str:
    """
    Get current UTC timestamp in ISO format with 'Z' suffix
    Timezone-aware to avoid deprecation warnings
    """
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

def clear_screen():
    os.system('clear')  # Always use 'clear' in Termux
    
# ============================================================================

# CONFIGURATION & CONSTANTS

# ============================================================================

class Config:
    """Centralized configuration management"""

    # Paths
    BASE_DIR = BASE_DIR / ".webxscan"
    HISTORY_PATH = BASE_DIR / "history.json"
    CACHE_PATH = BASE_DIR / "cache.json"
    LOG_PATH = BASE_DIR / "webxscan.log"
    CONFIG_PATH = BASE_DIR / "config.json"
    
    # Limits
    HISTORY_MAX = 200
    CACHE_TTL = 3600  # 1 hour
    MAX_CONCURRENT_SCANS = 2
    REQUEST_TIMEOUT = 15
    
    # API Keys
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    
    # Web Server
    WEB_HOST = "127.0.0.1"
    WEB_PORT = 5001
    WEB_DEBUG = False
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_PER_MINUTE = 10
    RATE_LIMIT_PER_HOUR = 100
    
    # Logging
    LOG_LEVEL = logging.INFO
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 3
    
    # Colors
    COLORS = {
        "primary": "deep_sky_blue2",
        "secondary": "slate_blue3",
        "success": "green3",
        "warning": "yellow3",
        "error": "red3",
        "info": "cyan2",
        "text": "grey84",
    }
    
    @classmethod
    def ensure_dirs(cls):
        cls.BASE_DIR.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def load_config(cls):
        try:
            if cls.CONFIG_PATH.exists():
                with open(cls.CONFIG_PATH, 'r') as f:
                    config = json.load(f)
                    for key, value in config.items():
                        if hasattr(cls, key):
                            setattr(cls, key, value)
        except Exception:
            pass
    
    @classmethod
    def save_config(cls):
        try:
            config = {
                "WEB_PORT": cls.WEB_PORT,
                "HISTORY_MAX": cls.HISTORY_MAX,
                "CACHE_TTL": cls.CACHE_TTL,
                "RATE_LIMIT_ENABLED": cls.RATE_LIMIT_ENABLED,
            }
            with open(cls.CONFIG_PATH, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass

Config.ensure_dirs()
Config.load_config()

# ============================================================================

# LOGGING SETUP

# ============================================================================

def setup_logging():
    logger = logging.getLogger("webxscan")
    logger.setLevel(Config.LOG_LEVEL)
    logger.handlers.clear()

    file_handler = RotatingFileHandler(
        Config.LOG_PATH,
        maxBytes=Config.LOG_MAX_BYTES,
        backupCount=Config.LOG_BACKUP_COUNT
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(file_handler)
    
    if RICH_AVAILABLE:
        console_handler = RichHandler(rich_tracebacks=True)
    else:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    
    logger.addHandler(console_handler)
    return logger

logger = setup_logging()

# ============================================================================

# UTILITY FUNCTIONS

# ============================================================================

console = Console() if RICH_AVAILABLE else None

def safe_print(message: str, style: str = None):
    if console:
        console.print(message, style=style)
    else:
        print(message)

def is_online(timeout: float = 2.0) -> bool:
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=timeout).close()
        return True
    except Exception:
        return False

def retry_with_backoff(func, tries: int = 3, delay: float = 0.5, backoff: float = 2.0, *args, **kwargs):
    for attempt in range(tries):
        try:
            return func(*args,**kwargs)
        except Exception as e:
            if attempt == tries - 1:
                raise
            logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay}s...")
            time.sleep(delay)
            delay *= backoff

def sanitize_input(user_input: str) -> str:
    """Sanitize user input (URL or IP)"""
    user_input = user_input.strip()
    user_input = re.sub(r'[<>"\']', '', user_input)

    # Add https if it looks like a domain without protocol
    if user_input and not user_input.startswith(("http://", "https://")) and not is_valid_ip(user_input):
        user_input = "https://" + user_input
    
    return user_input

def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_domain(domain: str) -> bool:
    """Validate domain name format"""
    if not domain or len(domain) > 255:
        return False
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def calculate_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def safe_json_dump(obj: Any) -> str:
    try:
        return json.dumps(obj, default=str, indent=2)
    except Exception:
        return str(obj)

# ============================================================================

# INPUT DETECTION & PARSING

# ============================================================================

class InputParser:
    """Parse and classify user input as URL, domain, or IP"""

    @staticmethod
    def parse(user_input: str) -> Dict[str, Any]:
        """
        Parse input and return structured info
        Returns: {
            'type': 'ip' | 'domain' | 'url',
            'original': str,
            'target': str (IP or domain),
            'url': str (full URL),
            'is_ip': bool
        }
        """
        user_input = sanitize_input(user_input)
        
        result = {
            'original': user_input,
            'type': None,
            'target': None,
            'url': None,
            'is_ip': False
        }
        
        # Check if it's a raw IP address
        if is_valid_ip(user_input):
            result['type'] = 'ip'
            result['target'] = user_input
            result['url'] = f"https://{user_input}"
            result['is_ip'] = True
            logger.info(f"Detected IP address: {user_input}")
            return result
        
        # Parse as URL
        parsed = urllib.parse.urlparse(user_input)
        netloc = parsed.netloc or parsed.path
        
        # Check if netloc is an IP
        if is_valid_ip(netloc):
            result['type'] = 'ip'
            result['target'] = netloc
            result['url'] = user_input if parsed.scheme else f"https://{netloc}"
            result['is_ip'] = True
            logger.info(f"Detected IP in URL: {netloc}")
            return result
        
        # It's a domain
        if validate_domain(netloc):
            result['type'] = 'domain'
            result['target'] = netloc
            result['url'] = user_input
            result['is_ip'] = False
            logger.info(f"Detected domain: {netloc}")
            return result
        
        # Fallback
        result['type'] = 'unknown'
        result['target'] = netloc
        result['url'] = user_input
        logger.warning(f"Could not classify input: {user_input}")
        return result

# ============================================================================

# CACHE MANAGEMENT

# ============================================================================

class CacheManager:
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.load_from_disk()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if time.time() - entry['timestamp'] < Config.CACHE_TTL:
                    logger.debug(f"Cache hit: {key}")
                    return entry['data']
                else:
                    del self._cache[key]
            return None
    
    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = {'data': value, 'timestamp': time.time()}
    
    def clear(self):
        with self._lock:
            self._cache.clear()
    
    def load_from_disk(self):
        try:
            if Config.CACHE_PATH.exists():
                with open(Config.CACHE_PATH, 'r') as f:
                    data = json.load(f)
                    current_time = time.time()
                    self._cache = {
                        k: v for k, v in data.items()
                        if current_time - v['timestamp'] < Config.CACHE_TTL
                    }
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
    
    def save_to_disk(self):
        try:
            with self._lock:
                with open(Config.CACHE_PATH, 'w') as f:
                    json.dump(self._cache, f)
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

cache_manager = CacheManager()

# ============================================================================

# HISTORY MANAGEMENT

# ============================================================================

class HistoryManager:
    def __init__(self):
        self._history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.load()

    def add(self, entry: Dict[str, Any]):
        with self._lock:
            self._history.insert(0, entry)
            self._history = self._history[:Config.HISTORY_MAX]
            self.save()
    
    def get_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._history.copy()
    
    def get_recent(self, count: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            return self._history[:count]
    
    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._history)
            if total == 0:
                return {
                    "total_scans": 0,
                    "unique_targets": 0,
                    "threat_distribution": {},
                    "average_confidence": 0,
                    "ip_scans": 0,
                    "domain_scans": 0
                }
            
            targets = set(entry.get('target') for entry in self._history)
            threats = defaultdict(int)
            confidences = []
            ip_count = 0
            domain_count = 0
            
            for entry in self._history:
                threat = entry.get('summary', {}).get('threat', 'Unknown')
                threats[threat] += 1
                
                if entry.get('is_ip'):
                    ip_count += 1
                else:
                    domain_count += 1
                
                full = entry.get('full', {})
                conf_str = full.get('confidence_score', '0%')
                try:
                    conf_val = int(conf_str.rstrip('%'))
                    confidences.append(conf_val)
                except:
                    pass
            
            return {
                "total_scans": total,
                "unique_targets": len(targets),
                "threat_distribution": dict(threats),
                "average_confidence": sum(confidences) / len(confidences) if confidences else 0,
                "ip_scans": ip_count,
                "domain_scans": domain_count
            }
    
    def clear(self):
        with self._lock:
            self._history.clear()
            self.save()
    
    def load(self):
        try:
            if Config.HISTORY_PATH.exists():
                with open(Config.HISTORY_PATH, 'r') as f:
                    self._history = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load history: {e}")
            self._history = []
    
    def save(self):
        try:
            with open(Config.HISTORY_PATH, 'w') as f:
                json.dump(self._history, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"Failed to save history: {e}")

history_manager = HistoryManager()

# ============================================================================

# DNS & REVERSE DNS

# ============================================================================

def get_reverse_dns(ip: str) -> Optional[str]:
    """Get reverse DNS (PTR record) for IP address"""
    try:
        if dns:
            rev_name = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = resolver.resolve(rev_name, "PTR")
            return str(answers[0]).rstrip('.')
        else:
            # Fallback to socket
            hostname,_, _ = socket.gethostbyaddr(ip)
            return hostname
    except Exception as e:
        logger.debug(f"Reverse DNS failed for {ip}: {e}")
        return None

def resolve_domain_to_ip(domain: str) -> Optional[str]:
    """Resolve domain to IP"""
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        logger.debug(f"DNS resolution failed for {domain}: {e}")
        return None

# ============================================================================

# DOMAIN/IP INFORMATION

# ============================================================================

def get_domain(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc or parsed.path

def format_date(date_obj: Any) -> str:
    if not date_obj:
        return "Not Available"

    try:
        if isinstance(date_obj, datetime):
            return date_obj.strftime("%d %B %Y")
        
        if isinstance(date_obj, str):
            for fmt in ['%Y-%m-%d', '%d-%m-%Y', '%Y/%m/%d']:
                try:
                    dt = datetime.strptime(date_obj, fmt)
                    return dt.strftime("%d %B %Y")
                except:
                    continue
            return date_obj
        
        return str(date_obj)
    except Exception:
        return "Not Available"

# ============================================================================

# WHOIS FUNCTIONS (Enhanced for IP)

# ============================================================================

def parse_date_string(date_str: str) -> Optional[datetime]:
    if not date_str:
        return None

    date_str = str(date_str).strip()
    date_str = re.sub(r'\s*\([^)]*\)\s*', '', date_str)
    date_str = re.sub(r'\s+[UG]MT.*$', '', date_str, flags=re.IGNORECASE)
    date_str = re.sub(r'[TZ]$', '', date_str)
    
    formats = [
        '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d-%b-%Y', '%d/%m/%Y', '%Y/%m/%d',
        '%d.%m.%Y', '%Y.%m.%d', '%b %d %Y', '%d %b %Y', '%d-%B-%Y',
        '%B %d, %Y', '%d %B %Y', '%Y%m%d'
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    
    return None

def rdap_lookup(target: str, is_ip: bool = False) -> Optional[Dict[str, Any]]:
    """RDAP lookup for domain or IP"""
    cache_key = f"rdap_{'ip' if is_ip else 'domain'}_{target}"
    cached = cache_manager.get(cache_key)
    if cached:
        return cached

    try:
        if is_ip:
            url = f"https://rdap.org/ip/{target}"
        else:
            url = f"https://rdap.org/domain/{target}"
        
        headers = {"User-Agent": "WebXScan/2.1"}
        response = requests.get(url, headers=headers, timeout=Config.REQUEST_TIMEOUT)
        
        if response.status_code != 200:
            return None
        
        data = response.json()
        result = {
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "network_name": None,
            "country": None
        }
        
        # Extract events
        for event in data.get("events", []):
            action = event.get("eventAction", "").lower()
            date_str = event.get("eventDate", "")
            
            if action == "registration":
                result["creation_date"] = parse_date_string(date_str)
            elif action == "expiration":
                result["expiration_date"] = parse_date_string(date_str)
        
        # Extract registrar/network info
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                result["registrar"] = entity.get("handle", "Unknown")
                break
        
        # IP-specific info
        if is_ip:
            result["network_name"] = data.get("name", "Unknown")
            result["country"] = data.get("country", "Unknown")
        
        if result["creation_date"] or result["expiration_date"] or result["network_name"]:
            cache_manager.set(cache_key, result)
            return result
        
        return None
    
    except Exception as e:
        logger.debug(f"RDAP lookup failed for {target}: {e}")
        return None

def get_whois_info(target: str, is_ip: bool = False) -> Dict[str, Any]:
    """Get WHOIS information for domain or IP"""
    result = {
        "creation_date": None,
        "expiration_date": None,
        "registrar": None,
        "network_name": None,
        "country": None,
        "method": None,
        "error": None
    }

    logger.debug(f"Attempting RDAP lookup for {target} (is_ip={is_ip})")
    rdap_data = rdap_lookup(target, is_ip)
    if rdap_data and (rdap_data.get("creation_date") or rdap_data.get("network_name")):
        result.update(rdap_data)
        result["method"] = "rdap"
        logger.info(f"WHOIS lookup successful via RDAP for {target}")
        return result
    
    result["error"] = "WHOIS unavailable (privacy protected or lookup failed)"
    logger.warning(f"WHOIS lookup failed for {target}")
    return result

# ============================================================================

# SSL CHECK (Enhanced for IP)

# ============================================================================

def check_ssl(target: str, is_ip: bool = False) -> Dict[str, Any]:
    """Check SSL certificate for domain or IP"""
    try:
        context = ssl.create_default_context()

        # For IPs, we need to handle SNI differently
        with socket.create_connection((target, 443), timeout=5) as sock:
            # Try with target as server_hostname (works for domains, might work for IPs)
            try:
                with context.wrap_socket(sock, server_hostname=target if not is_ip else None) as ssock:
                    cert = ssock.getpeercert()
            except:
                # Fallback: disable hostname check for IPs
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock) as ssock:
                    cert = ssock.getpeercert()
            
            if not cert:
                return {"valid": False, "error": "No certificate found"}
            
            not_before = cert.get("notBefore")
            not_after = cert.get("notAfter")
            
            valid_from = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
            valid_until = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            
            days_remaining = (valid_until - datetime.now()).days
            
            # Extract SANs (Subject Alternative Names)
            san_list = []
            for field in cert.get('subjectAltName', []):
                if field[0] == 'DNS':
                    san_list.append(field[1])
            
            return {
                "valid": True,
                "valid_from": format_date(valid_from),
                "valid_until": format_date(valid_until),
                "days_remaining": days_remaining,
                "issuer": dict(x[0] for x in cert.get('issuer', [])),
                "subject": dict(x[0] for x in cert.get('subject', [])),
                "san": san_list if san_list else None
            }
    except Exception as e:
        return {"valid": False, "error": str(e)}

# ============================================================================

# SECURITY HEADERS

# ============================================================================

def get_security_headers(headers: Dict[str, str]) -> Dict[str, str]:
    important_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME-Type Protection",
        "Referrer-Policy": "Referrer Policy"
    }

    result = {}
    for header, description in important_headers.items():
        value = None
        for key in headers:
            if key.lower() == header.lower():
                value = headers[key]
                break
        result[description] = value or "Missing"
    
    return result

# ============================================================================

# VIRUSTOTAL & THREAT INTELLIGENCE

# ============================================================================

def check_virustotal(target: str, is_ip: bool = False) -> Dict[str, Any]:
    """Check VirusTotal reputation for domain or IP"""
    vt_api_key = Config.VT_API_KEY.strip()

    if not vt_api_key:
        suspicious_keywords = ["login", "verify", "secure", "update", "account", "bank"]
        risk_score = sum(kw in target.lower() for kw in suspicious_keywords)
        
        return {
            "source": "local-fallback",
            "harmless": 1 if risk_score == 0 else 0,
            "malicious": 1 if risk_score >= 2 else 0,
            "suspicious": 1 if risk_score == 1 else 0,
            "note": "No VirusTotal API key. Using heuristic fallback."
        }
    
    cache_key = f"vt_{'ip' if is_ip else 'domain'}_{target}"
    cached = cache_manager.get(cache_key)
    if cached:
        return cached
    
    try:
        headers = {"x-apikey": vt_api_key}
        endpoint = "ip_addresses" if is_ip else "domains"
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{target}"
        
        response = requests.get(url, headers=headers, timeout=Config.REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            
            result = {
                "source": "virustotal-api",
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0)
            }
            
            cache_manager.set(cache_key, result)
            return result
        
        elif response.status_code == 401:
            return {"error": "Invalid API key", "source": "virustotal-api"}
        elif response.status_code == 404:
            return {"error": "Target not found", "source": "virustotal-api"}
        else:
            return {"error": f"API error: {response.status_code}", "source": "virustotal-api"}
    
    except Exception as e:
        logger.error(f"VirusTotal check failed: {e}")
        return {"error": str(e), "source": "virustotal-api"}

class ThreatIntelligence:
    @staticmethod
    def check_abuseipdb(ip: str) -> Dict[str, Any]:
        """Check IP reputation on AbuseIPDB (requires API key)"""
        api_key = os.getenv("ABUSEIPDB_API_KEY", "")

        if not api_key:
            return {"source": "abuseipdb", "status": "no_api_key"}
        
        cache_key = f"abuseipdb_{ip}"
        cached = cache_manager.get(cache_key)
        if cached:
            return cached
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": "90"}
            
            response = requests.get(url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json()["data"]
                
                result = {
                    "source": "abuseipdb",
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "threat_detected": data.get("abuseConfidenceScore", 0) > 50
                }
                
                cache_manager.set(cache_key, result)
                return result
            
            return {"source": "abuseipdb", "error": f"HTTP {response.status_code}"}
        
        except Exception as e:
            logger.debug(f"AbuseIPDB check failed: {e}")
            return {"source": "abuseipdb", "error": str(e)}
    
    @staticmethod
    def check_all_sources(url: str, target: str, is_ip: bool) -> Dict[str, Any]:
        results = {
            "checked_sources": 0,
            "threats_detected": 0,
            "sources": {},
            "overall_verdict": "unknown",
            "severity": "low"
        }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                'virustotal': executor.submit(check_virustotal, target, is_ip),
            }
            
            # Add IP-specific check
            if is_ip:
                futures['abuseipdb'] = executor.submit(ThreatIntelligence.check_abuseipdb, target)
            
            for source_name, future in futures.items():
                try:
                    result = future.result(timeout=10)
                    results["sources"][source_name] = result
                    results["checked_sources"] += 1
                    
                    if isinstance(result, dict):
                        if result.get("threat_detected"):
                            results["threats_detected"] += 1
                        elif result.get("malicious", 0) > 0:
                            results["threats_detected"] += 1
                        elif result.get("abuse_confidence_score", 0) > 50:
                            results["threats_detected"] += 1
                except Exception as e:
                    logger.warning(f"Threat check failed for {source_name}: {e}")
                    results["sources"][source_name] = {"error": str(e)}
        
        if results["threats_detected"] >= 2:
            results["overall_verdict"] = "malicious"
            results["severity"] = "critical"
        elif results["threats_detected"] == 1:
            results["overall_verdict"] = "suspicious"
            results["severity"] = "high"
        else:
            results["overall_verdict"] = "clean"
            results["severity"] = "low"
        
        return results

# ============================================================================

# THREAT CLASSIFICATION

# ============================================================================

def classify_threat(scan_data: Dict[str, Any]) -> str:
    """
    Classify threat level based on multiple factors
    Returns: "Safe", "Suspicious", "Risky", or "Dangerous"
    """
    # Check threat intelligence first (highest priority)
    threat_intel = scan_data.get("threat_intelligence", {})
    threats_detected = threat_intel.get("threats_detected", 0)
    checked_sources = threat_intel.get("checked_sources", 0)
    
    # Critical: Multiple sources reporting threats
    if threats_detected >= 2:
        return "Dangerous"
    
    # High risk: At least one source reporting threats
    if threats_detected >= 1:
        return "Risky"
    
    # Check VirusTotal data
    vt = scan_data.get("virustotal", {})
    if isinstance(vt, dict) and not vt.get("error"):
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        
        if malicious > 0:
            return "Dangerous"
        if suspicious > 1:
            return "Risky"
        if suspicious == 1:
            return "Suspicious"
    
    # Check SSL issues
    ssl_info = scan_data.get("ssl_info", {})
    if isinstance(ssl_info, dict):
        ssl_error = ssl_info.get("error")
        if ssl_error:
            error_str = str(ssl_error).lower()
            if any(word in error_str for word in ["certificate", "hostname", "verify"]):
                return "Risky"
    
    # Check security headers
    headers = scan_data.get("headers", {})
    if isinstance(headers, dict):
        missing_headers = sum(1 for v in headers.values() if v == "Missing")
        if missing_headers >= 4:
            return "Suspicious"
    
    # Default to safe if no threats found
    return "Safe"

def assess_confidence_and_recommendation(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate confidence score and provide recommendation
    Score is 0-100, where higher = safer
    """
    vt_data = result.get("virustotal", {})
    
    if not isinstance(vt_data, dict):
        vt_data = {}
    
    harmless = vt_data.get("harmless", 0) or 0
    malicious = vt_data.get("malicious", 0) or 0
    suspicious = vt_data.get("suspicious", 0) or 0
    
    # Start with 100 (safe)
    score = 100
    
    # Deduct for threats
    if malicious > 0:
        score -= (malicious * 30)  # Each malicious detection = -30
    if suspicious > 0:
        score -= (suspicious * 15)  # Each suspicious detection = -15
    
    # Check threat intelligence
    threat_intel = result.get("threat_intelligence", {})
    threats_detected = threat_intel.get("threats_detected", 0)
    
    if threats_detected >= 2:
        score = min(score, 20)  # Cap at 20% for multiple threats
    elif threats_detected == 1:
        score = min(score, 50)  # Cap at 50% for one threat
    
    # SSL issues
    ssl_info = result.get("ssl_info", {})
    if isinstance(ssl_info, dict) and ssl_info.get("error"):
        error_str = str(ssl_info.get("error", "")).lower()
        if any(word in error_str for word in ["certificate", "hostname", "verify", "expired"]):
            score -= 20
        else:
            score -= 5  # Minor SSL issue
    
    # Security headers check
    headers = result.get("headers", {})
    if isinstance(headers, dict):
        missing_headers = sum(1 for v in headers.values() if v == "Missing")
        score -= (missing_headers * 3)  # Each missing header = -3
    
    # WHOIS issues (minor)
    if result.get("whois_error") or result.get("whois") == "error":
        score -= 5
    
    # Ensure score is within bounds
    score = max(0, min(score, 100))
    
    # Determine threat level based on final score
    if score >= 80:
        threat_level = "Safe"
        recommendation = "✅ Safe — No significant threats detected."
        color = "green"
    elif score >= 60:
        threat_level = "Suspicious"
        recommendation = "⚠️ Suspicious — Minor concerns detected. Proceed with caution."
        color = "yellow"
    elif score >= 40:
        threat_level = "Risky"
        recommendation = "⚠️ Risky — Significant security concerns detected. Exercise caution!"
        color = "orange"
    else:
        threat_level = "Dangerous"
        recommendation = "🚨 Dangerous — Critical threats detected. Avoid this target!"
        color = "red"
    
    result["confidence_score"] = f"{score}%"
    result["threat_level"] = threat_level  # Update threat level here
    result["recommendation"] = recommendation
    result["threat_color"] = color
    
    return result

# ============================================================================

# MAIN SCAN FUNCTION (Enhanced for IP)

# ============================================================================

def scan_target(user_input: str, options: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
    """
    Main scanning function - supports both URLs and IP addresses
    """
    if options is None:
        options = {}

    # Parse input
    parsed = InputParser.parse(user_input)
    
    if parsed['type'] == 'unknown':
        return {
            "error": "Invalid input - must be a valid URL, domain, or IP address",
            "input": user_input
        }
    
    target = parsed['target']
    is_ip = parsed['is_ip']
    url = parsed['url']
    
    timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    result = {
        "target": target,
        "target_type": "ip" if is_ip else "domain",
        "url": url,
        "is_ip": is_ip,
        "scanned_at": timestamp,
        "scan_id": calculate_hash(f"{target}_{timestamp}")
    }
    
    online = is_online()
    result["_meta"] = {"online": online}
    
    logger.info(f"Starting scan for {target} (type={'IP' if is_ip else 'Domain'}, online={online})")
    
    # IP Resolution / Reverse DNS
    try:
        if online:
            if is_ip:
                # For IPs, do reverse DNS lookup
                reverse_dns = get_reverse_dns(target)
                result["reverse_dns"] = reverse_dns or "Not available"
                result["ip"] = target
                logger.debug(f"Reverse DNS for {target}: {reverse_dns}")
            else:
                # For domains, resolve to IP
                ip = retry_with_backoff(resolve_domain_to_ip, 2, 0.4, domain=target)
                result["ip"] = ip
                result["domain"] = target
                logger.debug(f"DNS resolved: {target} -> {ip}")
        else:
            raise RuntimeError("Network offline")
    except Exception as e:
        result["resolution_error"] = str(e)
        logger.warning(f"Resolution failed for {target}: {e}")
    
    # SSL Certificate Check
    try:
        if online:
            ssl_info = check_ssl(target, is_ip)
            result["ssl_info"] = ssl_info
            logger.debug(f"SSL check completed for {target}")
        else:
            result["ssl_info"] = {"error": "Network offline"}
    except Exception as e:
        result["ssl_info"] = {"error": str(e)}
        logger.warning(f"SSL check failed for {target}: {e}")
    
    # WHOIS Information
    try:
        if online:
            who_info = retry_with_backoff(get_whois_info, 2, 0.5, target=target, is_ip=is_ip)
        else:
            who_info = {"error": "offline"}
        
        if who_info.get("error"):
            result["whois"] = who_info["error"]
            result["whois_creation"] = "Not Available"
            result["whois_expiration"] = "Not Available"
        else:
            result["whois_creation"] = format_date(who_info.get("creation_date"))
            result["whois_expiration"] = format_date(who_info.get("expiration_date"))
            if who_info.get("registrar"):
                result["whois_registrar"] = who_info["registrar"]
            if who_info.get("network_name"):
                result["network_name"] = who_info["network_name"]
            if who_info.get("country"):
                result["country"] = who_info["country"]
            result["whois_method"] = who_info.get("method", "unknown")
        
        logger.debug(f"WHOIS check completed for {target}")
    except Exception as e:
        result["whois"] = f"error: {str(e)}"
        result["whois_creation"] = "Error"
        result["whois_expiration"] = "Error"
        logger.warning(f"WHOIS check failed for {target}: {e}")
    
    # HTTP Headers Check
    try:
        if online:
            headers = {"User-Agent": "WebXScan/2.1"}
            response = retry_with_backoff(
                requests.head,
                2,
                0.4,
                url=url,
                headers=headers,
                timeout=Config.REQUEST_TIMEOUT,
                allow_redirects=True
            )
            
            result["http_status"] = f"{response.status_code} {response.reason}"
            result["headers"] = get_security_headers(dict(response.headers))
            logger.debug(f"HTTP headers check completed for {target}")
        else:
            result["http_status"] = "offline - skipped"
    except Exception as e:
        result["http_error"] = str(e)
        logger.warning(f"HTTP check failed for {target}: {e}")
    
    # Threat Intelligence
    try:
        if online:
            logger.info(f"Running threat intelligence for {target}")
            threat_intel = ThreatIntelligence.check_all_sources(url, target, is_ip)
            result["threat_intelligence"] = threat_intel
            result["virustotal"] = threat_intel["sources"].get("virustotal", {})
            
            if is_ip and "abuseipdb" in threat_intel["sources"]:
                result["abuseipdb"] = threat_intel["sources"]["abuseipdb"]
            
            logger.info(f"Threat intelligence: {threat_intel['overall_verdict']} "
                       f"({threat_intel['threats_detected']}/{threat_intel['checked_sources']} sources)")
        else:
            result["threat_intelligence"] = {"error": "offline - skipped"}
            result["virustotal"] = {"error": "offline - skipped"}
    except Exception as e:
        result["threat_intelligence_error"] = str(e)
        logger.warning(f"Threat intelligence check failed: {e}")
    
    # Location
    result["location"] = result.get("ip", "Unknown")
    
    # Threat Classification
    # Threat Classification - Let assess_confidence_and_recommendation handle it
    try:
        # Initial classification (will be updated by confidence assessment)
        threat_intel = result.get("threat_intelligence", {})
        
        if threat_intel.get("threats_detected", 0) >= 2:
            result["threat_level"] = "Dangerous"
        elif threat_intel.get("threats_detected", 0) == 1:
            result["threat_level"] = "Risky"
        else:
            result["threat_level"] = classify_threat({
                "virustotal": result.get("virustotal"),
                "ssl_info": result.get("ssl_info"),
                "headers": result.get("headers", {}),
                "threat_intelligence": threat_intel
            })
    except Exception as e:
        result["threat_level"] = "Unknown"
        logger.warning(f"Threat classification failed: {e}")
    
    # Confidence Score & Recommendation - THIS WILL UPDATE threat_level
    result = assess_confidence_and_recommendation(result)
    
    # Save to history
    history_manager.add({
        "scanned_at": timestamp,
        "target": target,
        "is_ip": is_ip,
        "summary": {
            "ip": result.get("ip"),
            "threat": result.get("threat_level"),
            "confidence": result.get("confidence_score"),
            "threat_sources": result.get("threat_intelligence", {}).get("threats_detected", 0)
        },
        "full": result
    })
    
    logger.info(f"Scan completed for {target}: {result.get('threat_level')} "
               f"(Sources checked: {result.get('threat_intelligence', {}).get('checked_sources', 0)})")
    
    return result

# ============================================================================

# CONSOLE MODE

# ============================================================================

BANNER = r"""
                                                                                        
  @@@  @@@  @@@ @@@@@@@@ @@@@@@@                           
 @@!  @@!  @@! @@!      @@!  @@@                          
 @!!  !!@  @!@ @!!!:!   @!@!@!@                           
  !:  !!:  !!  !!:      !!:  !!!                          
   ::.:  :::   : :: ::: :: : ::                           
                                                          
      @@@  @@@           @@@@@@  @@@@@@@  @@@@@@  @@@  @@@
      @@!  !@@          !@@     !@@      @@!  @@@ @@!@!@@@
       !@@!@!  @!@!@!@!  !@@!!  !@!      @!@!@!@! @!@@!!@!
       !: :!!               !:! :!!      !!:  !!! !!:  !!!
      :::  :::          ::.: :   :: :: :  :   : : ::    : 
                                                                                                                                                                                                                                                                                        
  WEB XSCAN PROFESSIONAL | CREATED BY FRANK NET TOOLS
         Enterprise Security Scanner v2.1                 
"""

def pulse_banner(banner: str, cycles: int = 2, delay: float = 0.12):
    if not console:
        print(banner)
        return

    colors = ["cyan", "deep_sky_blue1", "blue", "medium_purple", "magenta"]
    
    for _ in range(cycles):
        for color in colors + list(reversed(colors)):
            console.clear()
            console.print("\n")
            console.print(banner, style=color)
            console.print(Panel.fit(
                "[deep_sky_blue2]WEB XSCAN PROFESSIONAL[/deep_sky_blue2]\n"
                "[white]Enterprise Security Scanner v2.1[/white]\n"
                "[cyan]Now with IP Address Support![/cyan]",
                title="[bold slate_blue3]⚙️ INITIALIZING[/bold slate_blue3]",
                subtitle="by Frank Net Tools",
                border_style="bright_magenta"
            ))
            time.sleep(delay)
            os.system("cls" if os.name == "nt" else "clear")

def display_scan_results(result: Dict[str, Any]):
    if not console or not Table:
        print(safe_json_dump(result))
        return

    target = result.get("target", "Unknown")
    target_type = result.get("target_type", "unknown")
    
    table = Table(
        title=f"Scan Results for {target} ({target_type.upper()})",
        title_style=Style(color=Config.COLORS["primary"], bold=True),
        border_style=Style(color=Config.COLORS["secondary"])
    )
    table.add_column("Check", style=Style(color=Config.COLORS["info"]))
    table.add_column("Result", style=Style(color=Config.COLORS["text"]))
    
    # Target info
    if result.get("is_ip"):
        table.add_row("IP Address", result.get("ip", "N/A"))
        table.add_row("Reverse DNS", result.get("reverse_dns", "N/A"))
        if result.get("network_name"):
            table.add_row("Network Name", result.get("network_name"))
        if result.get("country"):
            table.add_row("Country", result.get("country"))
    else:
        table.add_row("Domain", result.get("target", "N/A"))
        table.add_row("IP Address", result.get("ip", result.get("resolution_error", "N/A")))
    
    # SSL Info
    ssl_info = result.get("ssl_info", {})
    if isinstance(ssl_info, dict) and ssl_info.get("error"):
        table.add_row("SSL Status", f"[red]Error: {ssl_info.get('error')}[/red]")
    else:
        table.add_row("SSL Valid From", ssl_info.get("valid_from", "N/A"))
        table.add_row("SSL Valid Until", ssl_info.get("valid_until", "N/A"))
        if ssl_info.get("days_remaining"):
            days = ssl_info["days_remaining"]
            color = "green" if days > 30 else "yellow" if days > 7 else "red"
            table.add_row("SSL Days Remaining", f"[{color}]{days} days[/{color}]")
    
    # WHOIS Info
    table.add_row("WHOIS Created", result.get("whois_creation", "N/A"))
    table.add_row("WHOIS Expires", result.get("whois_expiration", "N/A"))
    if result.get("whois_registrar"):
        table.add_row("Registrar", result.get("whois_registrar"))
    
    # HTTP Status
    table.add_row("HTTP Status", result.get("http_status", result.get("http_error", "N/A")))
    
    # Security Headers
    headers = result.get("headers", {})
    for name, value in headers.items():
        color = "green" if value != "Missing" else "yellow"
        table.add_row(name, f"[{color}]{value}[/{color}]")
    
    # VirusTotal
    vt = result.get("virustotal", {})
    if isinstance(vt, dict):
        if vt.get("error"):
            vt_text = f"Error: {vt.get('error')}"
        else:
            mal = vt.get("malicious", 0)
            sus = vt.get("suspicious", 0)
            harm = vt.get("harmless", 0)
            vt_text = f"Malicious: {mal}, Suspicious: {sus}, Harmless: {harm}"
    else:
        vt_text = str(vt)
    table.add_row("VirusTotal", vt_text)
    
    # AbuseIPDB (for IPs)
    if result.get("is_ip") and result.get("abuseipdb"):
        abuse = result["abuseipdb"]
        if not abuse.get("error") and abuse.get("source") != "no_api_key":
            score = abuse.get("abuse_confidence_score", 0)
            color = "red" if score > 50 else "yellow" if score > 20 else "green"
            table.add_row("AbuseIPDB Score", f"[{color}]{score}%[/{color}]")
    
    # Threat Level
    threat_level = result.get("threat_level", "Unknown")
    threat_color = "red" if "dangerous" in threat_level.lower() else \
                   "yellow" if "risky" in threat_level.lower() or "suspicious" in threat_level.lower() else \
                   "green"
    table.add_row("Threat Level", f"[{threat_color}]{threat_level}[/{threat_color}]")
    
    console.print(table)
    
    # Threat Assessment Panel
    confidence = result.get("confidence_score", "N/A")
    recommendation = result.get("recommendation", "No recommendation")
    
    console.print(Panel(
        f"[{threat_color}]Threat Level:[/{threat_color}] {threat_level}\n"
        f"[{threat_color}]Confidence Score:[/{threat_color}] {confidence}\n"
        f"[{threat_color}]Recommendation:[/{threat_color}] {recommendation}",
        title="[bold]Threat Assessment[/bold]",
        border_style=threat_color
    ))

def run_console_mode():
    os.system("cls" if os.name == "nt" else "clear")
    pulse_banner(BANNER)

    if console:
        console.clear()
        console.print("\n")
        console.print(BANNER, style="deep_sky_blue2")
        console.print(Panel.fit(
            "[deep_sky_blue2]WEB XSCAN PROFESSIONAL v2.1[/deep_sky_blue2]\n"
            "[white]Enterprise Security Scanner Ready[/white]\n"
            "[cyan]✨ Now supports both URLs and IP addresses![/cyan]",
            title="[bold green]✅ SYSTEM ONLINE[/bold green]",
            border_style="green"
        ))
    else:
        print(BANNER)
        print("WEB XSCAN PROFESSIONAL v2.1\nSupports URLs and IP addresses\n")
    
    while True:
        try:
            if console:
                user_input = console.input(
                    "[cyan]🌐 Enter URL or IP to scan (or 'history', 'stats', 'exit'): [/cyan]"
                ).strip()
            else:
                user_input = input("🌐 Enter URL or IP to scan (or 'history', 'stats', 'exit'): ").strip()
            
            if not user_input:
                safe_print("⚠️ Input cannot be empty.", style="yellow")
                continue
            
            if user_input.lower() in ("exit", "quit"):
                safe_print("\n👋 Goodbye!", style="cyan")
                break
            
            if user_input.lower() == "history":
                history = history_manager.get_recent(10)
                if console:
                    console.print(Panel(f"Recent Scan History (last 10):"))
                    console.print(safe_json_dump(history))
                else:
                    print("\nRecent Scan History:")
                    print(safe_json_dump(history))
                continue
            
            if user_input.lower() == "stats":
                stats = history_manager.get_statistics()
                if console:
                    console.print(Panel("Scan Statistics"))
                    console.print(safe_json_dump(stats))
                else:
                    print("\nScan Statistics:")
                    print(safe_json_dump(stats))
                continue
            
            # Ask about export
            export_file = None
            if console:
                save_choice = console.input("[cyan]Save report to JSON? (y/N): [/cyan]").strip().lower()
            else:
                save_choice = input("Save report to JSON? (y/N): ").strip().lower()
            
            if save_choice == 'y':
                parsed = InputParser.parse(user_input)
                target = parsed['target']
                timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
                default_fn = f"{target.replace('.', '_').replace(':', '_')}_{timestamp}.json"
                
                if console:
                    export_file = console.input(f"[cyan]Filename (default: {default_fn}): [/cyan]").strip()
                else:
                    export_file = input(f"Filename (default: {default_fn}): ").strip()
                
                export_file = export_file or default_fn
            
            # Run scan with progress
            if console and Progress:
                with Progress(
                    SpinnerColumn(style=Config.COLORS["primary"]),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(complete_style=Config.COLORS["success"]),
                    TimeElapsedColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task("[cyan]Scanning...", total=100)
                    result = scan_target(user_input)
                    progress.advance(task, 100)
            else:
                print("Scanning...")
                result = scan_target(user_input)
            
            # Display results
            display_scan_results(result)
            
            # Export if requested
            if export_file:
                try:
                    with open(export_file, 'w', encoding='utf-8') as f:
                        json.dump(result, f, indent=2, default=str)
                    safe_print(f"\n✅ Report saved to: {export_file}", style="green")
                except Exception as e:
                    safe_print(f"\n❌ Failed to save report: {e}", style="red")
            
            if console:
                console.print(Panel(
                    "✅ Scan completed successfully!",
                    style=Style(color=Config.COLORS["success"])
                ))
            
        except KeyboardInterrupt:
            safe_print("\n\n⚠️ Interrupted by user", style="yellow")
            break
        except Exception as e:
            logger.error(f"Console mode error: {e}", exc_info=True)
            safe_print(f"\n❌ Error: {e}", style="red")

# ============================================================================

# WEB MODE

# ============================================================================

WEB_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web XScan Professional v2.1</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg: #0b0f14; --panel: #0f1720; --accent: #00bfff;
            --success: #2ecc71; --warning: #f6c343; --danger: #ff6b6b;
            --text: #98a8b9; --border: rgba(255,255,255,0.1);
        }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(180deg, #02040a, #071025);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            width: 100%;
            background: var(--panel);
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
            border: 1px solid var(--border);
        }
        h1 {
            color: var(--accent);
            text-align: center;
            margin-bottom: 5px;
            font-size: 2em;
        }
        .subtitle {
            text-align: center;
            color: var(--text);
            margin-bottom: 10px;
            opacity: 0.8;
        }
        .feature-badge {
            text-align: center;
            color: var(--success);
            margin-bottom: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }
        .input-group {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        input {
            flex: 1;
            padding: 15px;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: white;
            font-size: 16px;
        }
        input::placeholder { color: rgba(255,255,255,0.5); }
        button {
            padding: 15px 30px;
            background: linear-gradient(90deg, var(--success), #1fbd6b);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
            transition: transform 0.2s;
        }
        button:hover { transform: translateY(-2px); }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        .results {
            margin-top: 20px;
            padding: 20px;
            background: rgba(255,255,255,0.02);
            border-radius: 8px;
            border: 1px solid var(--border);
            display: none;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th { color: var(--accent); font-weight: 600; }
        .status { padding: 5px 10px; border-radius: 4px; display: inline-block; font-weight: bold; }
        .status-safe { background: #2ecc71; color: white; }
        .status-warn { background: #f39c12; color: white; }  /* Orange for Suspicious/Risky */
        .status-danger { background: #e74c3c; color: white; }
        .loading { text-align: center; padding: 20px; }
        .spinner {
            border: 3px solid rgba(255,255,255,0.1);
            border-top: 3px solid var(--accent);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .error { color: var(--danger); padding: 15px; text-align: center; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: rgba(255,255,255,0.05);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-value {
            font-size: 1.8em;
            font-weight: bold;
            color: var(--accent);
        }
        .stat-label { font-size: 0.85em; opacity: 0.8; margin-top: 5px; }
        .target-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: bold;
            margin-left: 8px;
        }
        .badge-ip { background: #e74c3c; color: white; }
        .badge-domain { background: #3498db; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Web XScan Professional</h1>
        <p class="subtitle">Enterprise Security Scanner v2.1</p>
        <p class="feature-badge">✨ Now supports both URLs and IP Addresses!</p>

        <div class="stats" id="stats"></div>
        
        <div class="input-group">
            <input type="text" id="urlInput" placeholder="Enter URL, domain, or IP address to scan..." />
            <button onclick="startScan()" id="scanBtn">Scan Now</button>
        </div>
        
        <div class="results" id="results"></div>
    </div>

    <script>
        async function loadStats() {
            try {
                const resp = await fetch('/stats');
                const stats = await resp.json();
                
                document.getElementById('stats').innerHTML = `
                    <div class="stat-card">
                        <div class="stat-value">${stats.total_scans}</div>
                        <div class="stat-label">Total Scans</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${stats.unique_targets}</div>
                        <div class="stat-label">Unique Targets</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${stats.ip_scans}</div>
                        <div class="stat-label">IP Scans</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${stats.domain_scans}</div>
                        <div class="stat-label">Domain Scans</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${Math.round(stats.average_confidence)}%</div>
                        <div class="stat-label">Avg Confidence</div>
                    </div>
                `;
            } catch (e) {
                console.error('Failed to load stats:', e);
            }
        }

        async function startScan() {
            const url = document.getElementById('urlInput').value.trim();
            const btn = document.getElementById('scanBtn');
            const results = document.getElementById('results');
            
            if (!url) {
                alert('Please enter a URL, domain, or IP address');
                return;
            }
            
            btn.disabled = true;
            results.style.display = 'block';
            results.innerHTML = '<div class="loading"><div class="spinner"></div><p>Scanning...</p></div>';
            
            try {
                const resp = await fetch('/scan?target=' + encodeURIComponent(url));
                const data = await resp.json();
                
                if (data.error) {
                    results.innerHTML = `<div class="error">❌ Error: ${data.error}</div>`;
                    return;
                }
                
                displayResults(data);
                loadStats();
            } catch (e) {
                results.innerHTML = `<div class="error">❌ Network error: ${e.message}</div>`;
            } finally {
                btn.disabled = false;
            }
        }

        function displayResults(data) {
            const threat = data.threat_level || 'Unknown';
            const confidence = parseInt(data.confidence_score) || 0;
            
            // Map threat level to CSS class
            let statusClass = 'status-safe';
            if (threat.toLowerCase() === 'dangerous' || confidence < 40) {
                statusClass = 'status-danger';
            } else if (threat.toLowerCase() === 'risky' || (confidence >= 40 && confidence < 60)) {
                statusClass = 'status-warn';
            } else if (threat.toLowerCase() === 'suspicious' || (confidence >= 60 && confidence < 80)) {
                statusClass = 'status-warn';
            } else if (threat.toLowerCase() === 'safe' || confidence >= 80) {
                statusClass = 'status-safe';
            }
            
            const targetType = data.is_ip ? 'IP' : 'Domain';
            const targetBadge = data.is_ip ? 'badge-ip' : 'badge-domain';
            
            let rows = `
                <tr><td>Target</td><td>${data.target} <span class="target-badge ${targetBadge}">${targetType}</span></td></tr>
            `;
            
            if (data.is_ip) {
                rows += `<tr><td>IP Address</td><td>${data.ip || 'N/A'}</td></tr>`;
                rows += `<tr><td>Reverse DNS</td><td>${data.reverse_dns || 'Not available'}</td></tr>`;
                if (data.network_name) {
                    rows += `<tr><td>Network</td><td>${data.network_name}</td></tr>`;
                }
                if (data.country) {
                    rows += `<tr><td>Country</td><td>${data.country}</td></tr>`;
                }
            } else {
                rows += `<tr><td>Domain</td><td>${data.target}</td></tr>`;
                rows += `<tr><td>IP Address</td><td>${data.ip || data.resolution_error || 'N/A'}</td></tr>`;
            }
            
            rows += `
                <tr><td>SSL Certificate</td><td>${data.ssl_info?.valid_from || 'N/A'} - ${data.ssl_info?.valid_until || 'N/A'}</td></tr>
                <tr><td>WHOIS Created</td><td>${data.whois_creation || 'N/A'}</td></tr>
                <tr><td>WHOIS Expires</td><td>${data.whois_expiration || 'N/A'}</td></tr>
                <tr><td>HTTP Status</td><td>${data.http_status || 'N/A'}</td></tr>
                <tr><td>Confidence Score</td><td>${data.confidence_score || 'N/A'}</td></tr>
                <tr><td>Threat Level</td><td><span class="status ${statusClass}">${threat}</span></td></tr>
                <tr><td>Recommendation</td><td>${data.recommendation || 'N/A'}</td></tr>
            `;
            
            const html = `
                <h3>Scan Results</h3>
                <table>
                    <tr><th>Check</th><th>Result</th></tr>
                    ${rows}
                </table>
            `;
            
            document.getElementById('results').innerHTML = html;
        }

        loadStats();
        
        document.getElementById('urlInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') startScan();
        });
    </script>
</body>
</html>
"""

def create_web_app():
    if not FLASK_AVAILABLE:
        raise RuntimeError("Flask not installed. Run: pip install flask flask-limiter")

    app = Flask("webxscan")
    app.secret_key = os.urandom(24)
    
    if Config.RATE_LIMIT_ENABLED:
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=[f"{Config.RATE_LIMIT_PER_HOUR} per hour"],
            storage_uri="memory://"
        )
    
    @app.route('/')
    def index():
        return render_template_string(WEB_TEMPLATE)
    
    @app.route('/scan')
    def scan():
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({"error": "Missing target parameter"}), 400
        
        try:
            result = scan_target(target)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Web scan error: {e}", exc_info=True)
            return jsonify({"error": str(e)}), 500
    
    @app.route('/history')
    def get_history():
        return jsonify(history_manager.get_recent(20))
    
    @app.route('/stats')
    def get_stats():
        return jsonify(history_manager.get_statistics())
    
    return app

def run_web_mode():
    try:
        app = create_web_app()
        
        def start_server():
            app.run(
                host=Config.WEB_HOST,
                port=Config.WEB_PORT,
                debug=Config.WEB_DEBUG,
                use_reloader=False
            )
        
        thread = threading.Thread(target=start_server, daemon=True)
        thread.start()
        
        time.sleep(1.5)
        
        url = f"http://{Config.WEB_HOST}:{Config.WEB_PORT}/"
        
        safe_print(f"\n✅ Web server running at: {url}", style="green")
        safe_print("✨ Now supports both URLs and IP addresses!", style="cyan")
        
        # Try to open browser
        if open_browser_termux(url):
            safe_print("✅ Browser opened successfully!", style="green")
        else:
            safe_print(f"\n📱 Could not auto-open browser.", style="yellow")
            safe_print(f"🌐 Manually open this URL in your browser:", style="cyan")
            safe_print(f"   {url}", style="bright_cyan")
            safe_print(f"\n💡 Or try: termux-open-url {url}", style="dim")
        
        safe_print("\nPress Ctrl+C to stop\n", style="yellow")
        
        input("Press ENTER to stop server...")
        
    except Exception as e:
        logger.error(f"Web mode error: {e}", exc_info=True)
        safe_print(f"❌ Failed to start web server: {e}", style="red")

# ============================================================================

# LAUNCHER MENU

# ============================================================================

def show_launcher_menu():
    os.system("cls" if os.name == "nt" else "clear")

    if console:
        console.print(BANNER, style="deep_sky_blue2")
        console.print("\n")
        console.print(Panel(
            "[cyan]WEB XSCAN PROFESSIONAL v2.1[/cyan]\n"
            "[green]✨ Now with IP Address Support![/green]\n\n"
            "[white]Select mode:[/white]\n"
            "1. Console Mode (CLI)\n"
            "2. Web Mode (Browser)\n"
            "3. View Statistics\n"
            "4. Clear History\n"
            "5. Exit",
            title="Launcher Menu",
            border_style="deep_sky_blue2"
        ))
        choice = console.input("[cyan]Enter choice (1-5): [/cyan]").strip()
    else:
        print(BANNER)
        print("\nWEB XSCAN PROFESSIONAL v2.1")
        print("✨ Now with IP Address Support!\n")
        print("1. Console Mode (CLI)")
        print("2. Web Mode (Browser)")
        print("3. View Statistics")
        print("4. Clear History")
        print("5. Exit")
        choice = input("\nEnter choice (1-5): ").strip()
    
    return choice

def main():
    logger.info("Web XScan Professional v2.1 starting...")

    if len(sys.argv) > 1:
        if "--web" in sys.argv or "-w" in sys.argv:
            run_web_mode()
            return
        elif "--console" in sys.argv or "-c" in sys.argv:
            run_console_mode()
            return
        elif "--help" in sys.argv or "-h" in sys.argv:
            print("Web XScan Professional v2.1")
            print("\nUsage: python webxscan.py [--web|--console|--help]")
            print("\nOptions:")
            print("  --web, -w       Start web mode directly")
            print("  --console, -c   Start console mode directly")
            print("  --help, -h      Show this help message")
            print("\nFeatures:")
            print("  ✅ Scan URLs and domains")
            print("  ✅ Scan IP addresses (IPv4 and IPv6)")
            print("  ✅ Reverse DNS lookup for IPs")
            print("  ✅ SSL certificate validation")
            print("  ✅ WHOIS information")
            print("  ✅ VirusTotal reputation check")
            print("  ✅ Security headers analysis")
            print("  ✅ Threat intelligence")
            return
    
    while True:
        try:
            choice = show_launcher_menu()
            
            if choice == '1':
                run_console_mode()
                if console:
                    console.input("\nPress ENTER to return to menu...")
                else:
                    input("\nPress ENTER to return to menu...")
            
            elif choice == '2':
                run_web_mode()
            
            elif choice == '3':
                stats = history_manager.get_statistics()
                if console:
                    console.print(Panel("📊 Scan Statistics"))
                    console.print(safe_json_dump(stats))
                    console.input("\nPress ENTER to continue...")
                else:
                    print("\n📊 Scan Statistics:")
                    print(safe_json_dump(stats))
                    input("\nPress ENTER to continue...")
            
            elif choice == '4':
                if console:
                    confirm = console.input("[yellow]Clear all history? (yes/no): [/yellow]").strip().lower()
                else:
                    confirm = input("Clear all history? (yes/no): ").strip().lower()
                
                if confirm == 'yes':
                    history_manager.clear()
                    cache_manager.clear()
                    safe_print("✅ History and cache cleared!", style="green")
                    time.sleep(1)
            
            elif choice == '5':
                safe_print("\n👋 Goodbye!", style="cyan")
                cache_manager.save_to_disk()
                break
            
            else:
                safe_print("❌ Invalid choice. Please enter 1-5.", style="red")
                time.sleep(1)
        
        except KeyboardInterrupt:
            safe_print("\n\n⚠️ Interrupted by user", style="yellow")
            break
        except Exception as e:
            logger.error(f"Launcher error: {e}", exc_info=True)
            safe_print(f"\n❌ Error: {e}", style="red")
            time.sleep(2)
    
    logger.info("Web XScan Professional v2.1 exiting...")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)
