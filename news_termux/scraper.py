#!/usr/bin/env python3
"""
Complete Cross-Platform Web Scraper & Information Tool
Compatible with Linux, Termux (Android), Windows, and macOS
Enhanced version with all original features preserved
"""

import sys
import os
import time
import re
import json
import platform
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import subprocess
import hashlib
import random
import secrets
import itertools
import shlex
import signal
import logging
import webbrowser
import urllib.parse
import concurrent.futures
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, asdict
from functools import lru_cache, wraps

# Third-party imports with fallbacks
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests urllib3")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("ERROR: beautifulsoup4 required. Install with: pip install beautifulsoup4")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("WARNING: python-dotenv not found. Environment variables from .env won't load.")
    load_dotenv = lambda: None

try:
    import feedparser
    FEEDPARSER_AVAILABLE = True
except ImportError:
    FEEDPARSER_AVAILABLE = False
    print("WARNING: feedparser not installed. RSS features disabled.")

try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False
    def tabulate(data, headers=None, tablefmt="grid", maxcolwidths=None, **kwargs):
        """Fallback tabulate for when library is not available"""
        if not data:
            return "No data"
        result = []
        if headers:
            result.append(" | ".join(str(h) for h in headers))
            result.append("-" * (len(result[0]) + len(headers) * 3))
        for row in data:
            result.append(" | ".join(str(cell) for cell in row))
        return "\n".join(result)

try:
    from requests_html import HTMLSession
    REQUESTS_HTML_AVAILABLE = True
except ImportError:
    REQUESTS_HTML_AVAILABLE = False
    print("WARNING: requests-html not installed. Google rate scraping disabled.")

# Colorama for cross-platform colors
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
        LIGHTGREEN_EX = LIGHTCYAN_EX = LIGHTBLACK_EX = LIGHTYELLOW_EX = LIGHTRED_EX = ""
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""

# =============================================================================
# PLATFORM DETECTION & CONFIGURATION
# =============================================================================

PLATFORM = platform.system().lower()
IS_TERMUX = os.path.exists('/data/data/com.termux')
IS_ANDROID = IS_TERMUX or 'ANDROID_ROOT' in os.environ
IS_WINDOWS = PLATFORM == 'windows'
IS_LINUX = PLATFORM == 'linux'
IS_MAC = PLATFORM == 'darwin'

# Environment variables
EXCHANGE_RATE_API_KEY = os.getenv("EXCHANGE_RATE_API_KEY")
NEWS_API_KEY = os.getenv("NEWS_API_KEY")
ABUSE_IPDB_API_KEY = os.getenv("ABUSE_IPDB_API_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")

# File paths
EVENT_FILE = "events.json"
EVENTS = []

# =============================================================================
# COMPREHENSIVE DATA STRUCTURES
# =============================================================================

CITY_MAPPING = {
    # Luzon
    "Manila": "Manila",
    "Batangas": "Batangas City",
    "Mindoro": "Calapan",
    "Laguna": "Santa Rosa",
    "Cavite": "Imus",
    "Tagaytay": "Tagaytay+Philippines",
    "La Union": "San Fernando",
    "Bulacan": "Malolos",
    "Pampanga": "Angeles",
    "Cagayan Valley": "Tuguegarao",
    "Ilocos": "Laoag",
    "Tuguegarao": "Tuguegarao",
    "Ilagan": "Isabela",
    "Sorsogon": "Sorsogon City",
    "Legazpi": "Legazpi City",
    # Visayas
    "Cebu City": "Cebu+Philippines",
    "Iloilo City": "Iloilo+Philippines",
    "Bohol": "Tagbilaran",
    "Leyte": "Tacloban",
    # Mindanao
    "Davao City": "Davao",
    "Cagayan de Oro": "Cagayan de Oro",
    "Zamboanga": "Zamboanga",
    "General Santos": "General+Santos",
    "Palawan": "Puerto Princesa",
}

REGIONS = {
    "Luzon": [
        "Manila",
        "Batangas",
        "Mindoro",
        "Laguna",
        "Cavite",
        "Tagaytay",
        "La Union",
        "Bulacan",
        "Pampanga",
        "Cagayan Valley",
        "Ilocos",
        "Tuguegarao",
        "Ilagan",
        "Sorsogon",
        "Legazpi",
    ],
    "Visayas": ["Cebu City", "Iloilo City", "Bohol", "Leyte"],
    "Mindanao": [
        "Davao City",
        "Cagayan de Oro",
        "Zamboanga",
        "General Santos",
        "Palawan",
    ],
}

FALLBACK_COORDS = {
    "Ilagan": "16.9754,121.8107",
    "Davao City": "7.0647,125.6088",
    "Cagayan de Oro": "8.4803,124.6498",
    "Zamboanga City": "6.9044,122.0761",
}

WIND_ARROWS = {
    "N": "↑", "NNE": "↑", "NE": "↗", "ENE": "↗",
    "E": "→", "ESE": "↘", "SE": "↘", "SSE": "↓",
    "S": "↓", "SSW": "↓", "SW": "↙", "WSW": "↙",
    "W": "←", "WNW": "↖", "NW": "↖", "NNW": "↑",
}

currency_data = {
    "PHILIPPINES": {"code": "PHP", "flag": "🇵🇭"},
    "UNITED STATES": {"code": "USD", "flag": "🇺🇸"},
    "CANADA": {"code": "CAD", "flag": "🇨🇦"},
    "MEXICO": {"code": "MXN", "flag": "🇲🇽"},
    "BRAZIL": {"code": "BRL", "flag": "🇧🇷"},
    "ARGENTINA": {"code": "ARS", "flag": "🇦🇷"},
    "VENEZUELA": {"code": "VES", "flag": "🇻🇪"},
    "EUROPEAN MONETARY UNION": {"code": "EUR", "flag": "🇪🇺"},
    "UNITED KINGDOM": {"code": "GBP", "flag": "🇬🇧"},
    "SWITZERLAND": {"code": "CHF", "flag": "🇨🇭"},
    "SWEDEN": {"code": "SEK", "flag": "🇸🇪"},
    "NORWAY": {"code": "NOK", "flag": "🇳🇴"},
    "DENMARK": {"code": "DKK", "flag": "🇩🇰"},
    "JAPAN": {"code": "JPY", "flag": "🇯🇵"},
    "CHINA": {"code": "CNY", "flag": "🇨🇳"},
    "KOREA": {"code": "KRW", "flag": "🇰🇷"},
    "SINGAPORE": {"code": "SGD", "flag": "🇸🇬"},
    "THAILAND": {"code": "THB", "flag": "🇹🇭"},
    "INDONESIA": {"code": "IDR", "flag": "🇮🇩"},
    "MALAYSIA": {"code": "MYR", "flag": "🇲🇾"},
    "INDIA": {"code": "INR", "flag": "🇮🇳"},
    "TAIWAN": {"code": "TWD", "flag": "🇹🇼"},
    "PAKISTAN": {"code": "PKR", "flag": "🇵🇰"},
    "UNITED ARAB EMIRATES": {"code": "AED", "flag": "🇦🇪"},
    "SAUDI ARABIA": {"code": "SAR", "flag": "🇸🇦"},
    "BAHRAIN": {"code": "BHD", "flag": "🇧🇭"},
    "KUWAIT": {"code": "KWD", "flag": "🇰🇼"},
    "SYRIA": {"code": "SYP", "flag": "🇸🇾"},
    "SOUTH AFRICA": {"code": "ZAR", "flag": "🇿🇦"},
    "AUSTRALIA": {"code": "AUD", "flag": "🇦🇺"},
    "NEW ZEALAND": {"code": "NZD", "flag": "🇳🇿"},
    "HONGKONG": {"code": "HKD", "flag": "🇭🇰"},
    "BRUNEI": {"code": "BND", "flag": "🇧🇳"},
}

currency_groups = {
    "Americas 🌎": ["USD", "CAD", "MXN", "BRL", "ARS", "VES"],
    "Europe 🇪🇺": ["EUR", "GBP", "CHF", "SEK", "NOK", "DKK"],
    "Asia 🌏": ["JPY", "CNY", "KRW", "SGD", "THB", "IDR", "MYR", "INR", "TWD", "PKR"],
    "Middle East 🌍": ["AED", "SAR", "BHD", "KWD", "SYP"],
    "Africa 🌍": ["ZAR"],
    "Oceania 🌊": ["AUD", "NZD"],
    "Others": ["HKD", "BND"],
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def clear_screen():
    """Cross-platform screen clear"""
    if IS_WINDOWS:
        os.system("cls")
    else:
        os.system("clear")

def press_enter_to_continue():
    """Wait for user input"""
    try:
        input(f"\n{Fore.LIGHTBLACK_EX}Press Enter to continue...{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print("\nOperation cancelled.")

def pause():
    """Alias for press_enter_to_continue"""
    press_enter_to_continue()

def print_header(text, char="="):
    """Print a formatted header"""
    width = 80
    print(f"\n{Fore.CYAN}{char * width}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{text.center(width)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{char * width}{Style.RESET_ALL}")

def print_section(text):
    """Print a section divider"""
    print(f"\n{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{text}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")

def get_timestamp():
    """Get current timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def safe_request(url, timeout=10, **kwargs):
    """Make a safe HTTP request with error handling"""
    try:
        headers = kwargs.get('headers', {})
        if 'User-Agent' not in headers:
            headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        kwargs['headers'] = headers
        
        response = requests.get(url, timeout=timeout, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}⚠️ Request timeout for {url}{Style.RESET_ALL}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}⚠️ Request error: {e}{Style.RESET_ALL}")
        return None

def wind_arrow(raw_wind):
    """Convert wind direction to arrow"""
    if raw_wind:
        parts = raw_wind.split()
        direction = parts[0].upper() if len(parts) > 0 else ""
        speed = parts[1] if len(parts) > 1 else ""
        arrow = WIND_ARROWS.get(direction, "")
        return f"{arrow}{speed}"
    return raw_wind

def get_google_rate(from_currency: str, to_currency: str = "PHP"):
    """
    Scrape Google's finance widget for currency pair
    Uses multiple methods for reliability
    """
    # Method 1: Try with requests-html (if available)
    if REQUESTS_HTML_AVAILABLE:
        try:
            session = HTMLSession()
            url = f"https://www.google.com/finance/quote/{from_currency}-{to_currency}"
            r = session.get(url, timeout=15)
            
            # Try without rendering first (faster)
            rate_elem = r.html.find("div.YMlKec.fxKbKc", first=True)
            if rate_elem:
                rate_text = rate_elem.text.replace(",", "").strip()
                return float(rate_text)
        except Exception:
            pass
    
    # Method 2: Use regular requests with BeautifulSoup
    try:
        url = f"https://www.google.com/finance/quote/{from_currency}-{to_currency}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://www.google.com/',
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Try multiple selectors
        selectors = [
            'div.YMlKec.fxKbKc',
            'div[data-last-price]',
            'div.YMlKec',
            'span.fxKbKc'
        ]
        
        for selector in selectors:
            elements = soup.select(selector)
            for elem in elements:
                text = elem.get_text(strip=True)
                # Look for number pattern
                import re
                match = re.search(r'(\d+\.?\d*)', text.replace(',', ''))
                if match:
                    try:
                        rate = float(match.group(1))
                        if rate > 0 and rate < 10000:  # Sanity check
                            return rate
                    except:
                        continue
        
        # Try data attributes
        rate_div = soup.find('div', {'data-last-price': True})
        if rate_div:
            try:
                return float(rate_div['data-last-price'])
            except:
                pass
                
    except Exception:
        pass
    
    return None

# =============================================================================
# CURRENCY EXCHANGE RATES
# =============================================================================

def get_currency_rate():
    """Fetch and display currency exchange rates vs PHP"""
    print(Fore.CYAN + "=" * 75)
    print(Fore.YELLOW + "          🌍 Currency Exchange Rates vs Philippine Peso (PHP) 🌍")
    print(Fore.CYAN + "=" * 75 + Style.RESET_ALL)
    
    if not EXCHANGE_RATE_API_KEY:
        print(Fore.RED + "⚠️  Error: EXCHANGE_RATE_API_KEY is missing in .env file.")
        print(Fore.YELLOW + "\nTo get an API key:")
        print("1. Visit: https://forexrateapi.com/")
        print("2. Sign up for free account")
        print("3. Add key to .env file as: EXCHANGE_RATE_API_KEY=your_key_here")
        pause()
        return
    
    base = "USD"
    codes = [info["code"] for info in currency_data.values()]
    url = f"https://api.forexrateapi.com/v1/latest?api_key={EXCHANGE_RATE_API_KEY}&base={base}&currencies={','.join(codes)}"
    
    try:
        res = requests.get(url, timeout=10).json()
        if not res.get("success"):
            print(Fore.RED + f"⚠️  API error: {res.get('message')}")
            pause()
            return
        
        rates = res.get("rates", {})
        usd_php = rates.get("PHP")
        if not usd_php:
            print(Fore.RED + "⚠️  Could not retrieve PHP rate.")
            pause()
            return
        
        # Display USD vs PHP
        print(Fore.GREEN + f"\nForexRate API:  1 USD = {usd_php:.2f} PHP {currency_data['UNITED STATES']['flag']}")
        
        if REQUESTS_HTML_AVAILABLE:
            google_usd = get_google_rate("USD", "PHP")
            if google_usd:
                diff = google_usd - usd_php
                ind = Fore.GREEN + " 🔺" if diff > 0 else Fore.RED + " 🔻" if abs(diff) > 0.01 else ""
                print(Fore.MAGENTA + f"Google:        1 USD = {google_usd:.2f} PHP {currency_data['UNITED STATES']['flag']}{ind}\n")
        
        # Loop by region
        for region, wcodes in currency_groups.items():
            has = any(rates.get(c) for c in wcodes if c not in (base, "PHP"))
            if not has:
                continue
            
            print(Fore.CYAN + "-" * 75)
            print(Fore.YELLOW + Style.BRIGHT + f"{region}")
            print(Fore.CYAN + "-" * 75)
            print(Fore.LIGHTBLUE_EX + f"{'Code':<6} {'API Rate (PHP)':<18} {'Google Rate (PHP)':<18} {'Country / Flag'}")
            print(Fore.CYAN + "-" * 75)
            
            for code in wcodes:
                if code in (base, "PHP"):
                    continue
                
                country = next((c for c, d in currency_data.items() if d["code"] == code), code)
                rate = rates.get(code)
                
                if rate:
                    api_r = usd_php / rate
                    api_str = f"{api_r:.2f}"
                    
                    # Try to get Google rate for this currency
                    gr = get_google_rate(code, "PHP")
                    gr_str = f"{gr:.2f}" if gr else "N/A"
                    diff = gr - api_r if gr else 0
                    ind = Fore.GREEN + " 🔺" if gr and diff > 0.01 else Fore.RED + " 🔻" if gr and diff < -0.01 else ""
                    
                    flag = currency_data.get(country, {}).get("flag", "")
                    print(f"{Fore.GREEN}{code:<6}{api_str:<18}{gr_str:<18}{Style.RESET_ALL}{country} {flag}{ind}")
                else:
                    flag = currency_data.get(country, {}).get("flag", "")
                    print(f"{Fore.RED}{code:<6}{'N/A':<18}{'N/A':<18}{Style.RESET_ALL}{country} {flag}")
        
        print(Fore.CYAN + "-" * 75)
        print(Fore.LIGHTBLACK_EX + "Note: 🔺 Google higher, 🔻 Google lower | Rates may vary by provider.")
        if not REQUESTS_HTML_AVAILABLE:
            print(Fore.LIGHTBLACK_EX + "      Install requests-html for Google rate comparison: pip install requests-html")
        print(Fore.CYAN + "-" * 75)
        
    except Exception as e:
        print(Fore.RED + f"⚠️  Error: {e}")
    
    pause()

# =============================================================================
# TSUNAMI FUNCTIONS
# =============================================================================

def fetch_tsunami():
    """Fetch tsunami alerts from PHIVOLCS"""
    url = "https://tsunami.phivolcs.dost.gov.ph/"
    print_header("🌊 Recent Tsunami Info (PHIVOLCS)")
    
    try:
        resp = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        rows = []

        # Find advisory table
        table = soup.find("table")
        if table:
            for tr in table.find_all("tr")[1:]:  # skip header
                cols = [c.get_text(strip=True) for c in tr.find_all("td")]
                if cols:
                    rows.append(cols)

        if rows:
            # --- Color coding helper ---
            def colorize(row):
                remark = row[-1].lower()
                if "warning" in remark:
                    row[-1] = Fore.RED + Style.BRIGHT + row[-1] + Style.RESET_ALL
                elif "advisory" in remark:
                    row[-1] = Fore.YELLOW + Style.BRIGHT + row[-1] + Style.RESET_ALL
                elif "information" in remark:
                    row[-1] = Fore.CYAN + Style.BRIGHT + row[-1] + Style.RESET_ALL
                return row

            # --- Latest alert ---
            latest = colorize(rows[0].copy())
            print("\n🚨 Latest Tsunami Alert")
            print(
                tabulate(
                    [latest],
                    headers=["Date/Time", "Magnitude/Info", "Location", "Remarks"],
                    tablefmt="fancy_grid",
                )
            )

            # --- Other updates ---
            if len(rows) > 1:
                colored_rows = [colorize(r.copy()) for r in rows[1:]]
                print("\n📋 Other Tsunami Updates")
                print(
                    tabulate(
                        colored_rows,
                        headers=["Date/Time", "Magnitude/Info", "Location", "Remarks"],
                        tablefmt="pretty",
                    )
                )

            # --- Philippines-only updates ---
            ph_rows = [colorize(r.copy()) for r in rows if "philippine" in r[2].lower()]
            if ph_rows:
                print("\n🇵🇭 Philippines-Only Advisories")
                print(
                    tabulate(
                        ph_rows,
                        headers=["Date/Time", "Magnitude/Info", "Location", "Remarks"],
                        tablefmt="pretty",
                    )
                )
            else:
                print("\n🇵🇭 No recent advisories for the Philippines.")

        else:
            print(f"{Fore.YELLOW}No recent tsunami advisory found{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}Error fetching tsunami data: {e}{Style.RESET_ALL}")
    
    pause()

# =============================================================================
# NEWS FUNCTIONS
# =============================================================================

def get_global_tech_news():
    """Fetch global tech news using NewsAPI"""
    print_header("🌍 Latest Global Tech News")
    
    if not NEWS_API_KEY or NEWS_API_KEY.strip() == "":
        print(f"{Fore.RED}❌ ERROR: NEWS_API_KEY not set in .env file{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}\nTo get an API key:")
        print("1. Visit: https://newsapi.org/")
        print("2. Sign up for free account")
        print("3. Add key to .env file as: NEWS_API_KEY=your_key_here")
        pause()
        return
    
    url = "https://newsapi.org/v2/top-headlines"
    params = {
        "category": "technology",
        "language": "en",
        "pageSize": 20,
        "apiKey": NEWS_API_KEY,
    }
    
    response = safe_request(url, params=params)
    if not response:
        pause()
        return
    
    try:
        data = response.json()
        
        if data.get("status") != "ok":
            print(f"{Fore.RED}❌ Failed to fetch news: {data.get('message', 'Unknown error')}{Style.RESET_ALL}")
            pause()
            return
        
        articles = data.get("articles", [])
        if not articles:
            print(f"{Fore.YELLOW}⚠️ No technology news found{Style.RESET_ALL}")
            pause()
            return
        
        for i, article in enumerate(articles, 1):
            title = article.get("title", "No title")
            source = article.get("source", {}).get("name", "Unknown")
            url = article.get("url", "")
            
            print(f"\n{Fore.GREEN}{i}. {title}{Style.RESET_ALL}")
            print(f"   {Fore.CYAN}Source: {source}{Style.RESET_ALL}")
            if url:
                print(f"   {Fore.LIGHTBLACK_EX}Link: {url}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
    
    pause()

def get_rss_news(feed_urls, title="News"):
    """Generic RSS news fetcher"""
    if not FEEDPARSER_AVAILABLE:
        print(f"{Fore.RED}❌ feedparser not installed. Install with: pip install feedparser{Style.RESET_ALL}")
        pause()
        return
    
    print_header(f"📰 {title}")
    
    for feed_url in feed_urls:
        try:
            feed = feedparser.parse(feed_url)
            source_title = feed.feed.get("title", "Unknown Source")
            
            print(f"\n{Fore.CYAN}📡 Source: {source_title}{Style.RESET_ALL}")
            
            entries = feed.entries[:20]
            for i, entry in enumerate(entries, 1):
                print(f"  {i}. {entry.title}")
        
        except Exception as e:
            print(f"{Fore.RED}⚠️ Error fetching {feed_url}: {e}{Style.RESET_ALL}")
    
    pause()

def get_philippines_news():
    """Fetch Philippine news via RSS"""
    feeds = [
        "https://newsinfo.inquirer.net/feed",
        "https://www.philstar.com/rss/headlines",
        "https://news.abs-cbn.com/rss/latest",
        "https://www.gmanetwork.com/news/rss/latest/rss",
    ]
    get_rss_news(feeds, "🇵🇭 Philippines Latest News")

def get_global_news():
    """Fetch global news via RSS"""
    feeds = [
        "http://feeds.bbci.co.uk/news/world/rss.xml",
        "http://rss.cnn.com/rss/edition_world.rss",
        "https://feeds.reuters.com/reuters/worldNews",
    ]
    get_rss_news(feeds, "🌍 Global News Headlines")

def get_tech_news():
    """Scrape TechCrunch headlines"""
    print_header("📱 Latest Technology News (TechCrunch)")
    
    url = "https://techcrunch.com/"
    
    response = safe_request(url)
    if not response:
        pause()
        return
    
    try:
        soup = BeautifulSoup(response.text, "html.parser")
        headlines = soup.select("h2.post-block__title a") or soup.select("h3 a")
        
        if not headlines:
            print(f"{Fore.YELLOW}Could not find headlines. Website structure may have changed.{Style.RESET_ALL}")
            pause()
            return
        
        for i, headline in enumerate(headlines[:20], 1):
            title = headline.get_text(strip=True)
            link = headline.get("href")
            
            print(f"\n{Fore.GREEN}{i}. {title}{Style.RESET_ALL}")
            if link and "techcrunch.com" in link:
                print(f"   {Fore.LIGHTBLACK_EX}Link: {link}{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
    
    pause()

def get_microsoft_news():
    """Fetch Microsoft-related news"""
    if not NEWS_API_KEY or NEWS_API_KEY.strip() == "":
        print(f"{Fore.RED}❌ ERROR: NEWS_API_KEY not set in .env file{Style.RESET_ALL}")
        pause()
        return
    
    print_header("💻 Microsoft Tech News")
    
    url = "https://newsapi.org/v2/everything"
    params = {"q": "Microsoft", "language": "en", "pageSize": 20, "apiKey": NEWS_API_KEY}
    
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if data.get("status") == "ok" and data.get("articles"):
            for i, article in enumerate(data["articles"], start=1):
                title = article.get("title", "No title")
                source = article.get("source", {}).get("name", "Unknown source")
                print(f"{i}. {title} ({source})")
        else:
            print(f"{Fore.YELLOW}⚠️ No Microsoft news available right now.{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}❌ Error fetching Microsoft news: {e}{Style.RESET_ALL}")
    
    pause()

def get_ph_news():
    """Scrape Rappler news"""
    print_header("📰 Live News from the Philippines (Rappler)")
    
    url = "https://www.rappler.com/"
    
    response = safe_request(url)
    if not response:
        pause()
        return
    
    try:
        soup = BeautifulSoup(response.text, "html.parser")
        headlines = soup.select("h3 a") or soup.select("article a")
        
        if not headlines:
            print(f"{Fore.YELLOW}⚠️ Could not find headlines{Style.RESET_ALL}")
            pause()
            return
        
        for i, headline in enumerate(headlines[:20], 1):
            title = headline.get_text(strip=True)
            link = headline.get("href")
            
            if link and link.startswith("/"):
                link = "https://www.rappler.com" + link
            
            print(f"\n{Fore.GREEN}{i}. {title}{Style.RESET_ALL}")
            if link:
                print(f"   {Fore.LIGHTBLACK_EX}Link: {link}{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
    
    pause()

# =============================================================================
# WEATHER FUNCTIONS
# =============================================================================

def fetch_weather(city, retries=2):
    """Fetch weather from wttr.in with color coding"""
    query = CITY_MAPPING.get(city, city).replace(" ", "+")
    url = f"https://wttr.in/{query}?format=%C+%t+%w+%h+%p+%m"
    
    for attempt in range(retries + 1):
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                raw = response.text.strip()
                
                # Retry with fallback coordinates if unknown
                if "Unknown" in raw and city in FALLBACK_COORDS:
                    latlon = FALLBACK_COORDS[city]
                    url2 = f"https://wttr.in/{latlon}?format=%C+%t+%w+%h+%p+%m"
                    response2 = requests.get(url2, timeout=10)
                    if response2.status_code == 200:
                        raw = response2.text.strip()
                
                # Color coding based on condition
                condition_text = " ".join(raw.split()[0:3]).lower()
                color = Style.RESET_ALL
                
                if any(k in condition_text for k in ["sun", "clear"]):
                    color = Fore.YELLOW
                elif any(k in condition_text for k in ["partly", "cloud", "overcast"]):
                    color = Fore.CYAN
                elif any(k in condition_text for k in ["rain", "shower", "drizzle", "patchy", "light rain"]):
                    color = Fore.BLUE
                elif any(k in condition_text for k in ["thunder", "storm", "lightning"]):
                    color = Fore.MAGENTA
                elif any(k in condition_text for k in ["fog", "mist", "haze"]):
                    color = Fore.LIGHTBLACK_EX
                elif any(k in condition_text for k in ["snow", "ice", "sleet"]):
                    color = Fore.WHITE
                
                return f"{color}{raw}{Style.RESET_ALL}"
        
        except requests.exceptions.Timeout:
            if attempt < retries:
                time.sleep(1)
                continue
            else:
                return f"{Fore.RED}⚠️ Timeout{Style.RESET_ALL}"
        except Exception as e:
            return f"{Fore.RED}⚠️ Error: {e}{Style.RESET_ALL}"
    
    return f"{Fore.RED}⚠️ Unable to fetch{Style.RESET_ALL}"

def get_philippines_weather():
    """Display comprehensive Philippines weather dashboard"""
    print(Fore.CYAN + "=" * 75)
    print(Fore.YELLOW + "          🌏 Philippines Weather Dashboard 🌏")
    print(Fore.CYAN + "=" * 75 + Style.RESET_ALL)
    
    print("\n📡 Live Weather by Region and City:\n")
    
    for region, cities in REGIONS.items():
        print(Fore.CYAN + f"--- {region} ---" + Style.RESET_ALL)
        for city in cities:
            weather = fetch_weather(city)
            
            # Parse and colorize temperature
            try:
                parts = weather.split()
                if len(parts) >= 4:
                    condition = parts[0]
                    temp = parts[1]
                    wind = wind_arrow(parts[2]) if len(parts) > 2 else ""
                    humidity = parts[3] if len(parts) > 3 else ""
                    precip = parts[4] if len(parts) > 4 else ""
                    moon = parts[5] if len(parts) > 5 else ""
                    
                    # Colorize temperature
                    temp_val = int(temp.strip("+°C")) if "°C" in temp else 0
                    if temp_val >= 35:
                        temp_color = Fore.RED + temp
                    elif temp_val >= 30:
                        temp_color = Fore.YELLOW + temp
                    else:
                        temp_color = Fore.CYAN + temp
                    
                    print(f"{city:<20}: {condition} {temp_color} {wind} {humidity} {precip} {moon}")
                else:
                    print(f"{city:<20}: {weather}")
            except:
                print(f"{city:<20}: {weather}")
            
            time.sleep(0.3)
        print("")
    
    print(Fore.CYAN + "-" * 75)
    print(Fore.LIGHTBLACK_EX + "Note: Live weather from wttr.in")
    print(Fore.CYAN + "-" * 75)
    
    pause()

# =============================================================================
# EARTHQUAKE FUNCTIONS
# =============================================================================

def fetch_earthquake():
    """Fetch earthquake data from USGS"""
    print_header("🌍 Recent Earthquakes (USGS)")
    
    urls = {
        "Last 24 Hours": "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson",
        "Last 7 Days": "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_week.geojson",
        "Last 14 Days": "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_month.geojson",
    }
    
    for label, url in urls.items():
        response = safe_request(url)
        if not response:
            continue
        
        try:
            data = response.json()
            ph_rows = []
            global_rows = []
            
            for feat in data["features"]:
                prop = feat["properties"]
                place = prop.get("place", "Unknown")
                mag = prop.get("mag", 0)
                ts = prop.get("time", 0)
                timestamp = datetime.utcfromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M:%S UTC")
                
                # Color magnitude
                if mag >= 5.0:
                    mag_str = f"{Style.BRIGHT}{Fore.RED}{mag:.1f}{Style.RESET_ALL}"
                else:
                    mag_str = f"{Style.BRIGHT}{Fore.YELLOW}{mag:.1f}{Style.RESET_ALL}"
                
                row = [place[:60], mag_str, timestamp, ts]
                
                if "Philippines" in place:
                    ph_rows.append(row)
                else:
                    global_rows.append(row)
            
            # Sort by timestamp (newest first)
            ph_rows.sort(key=lambda x: x[3], reverse=True)
            global_rows.sort(key=lambda x: x[3], reverse=True)
            
            # Remove timestamp column
            ph_rows = [r[:3] for r in ph_rows]
            global_rows = [r[:3] for r in global_rows]
            
            print(f"\n{Fore.YELLOW}🇵🇭 Earthquakes in Philippines ({label}){Style.RESET_ALL}")
            if ph_rows:
                print(tabulate(ph_rows, headers=["Location", "Magnitude", "Timestamp"], tablefmt="fancy_grid"))
            else:
                print(f"{Fore.GREEN}No recent earthquakes in the Philippines{Style.RESET_ALL}")
            
            print(f"\n{Fore.YELLOW}🌐 Earthquakes Worldwide ({label}){Style.RESET_ALL}")
            if global_rows:
                print(tabulate(global_rows[:20], headers=["Location", "Magnitude", "Timestamp"], tablefmt="fancy_grid"))
        
        except Exception as e:
            print(f"{Fore.RED}⚠️ Error parsing earthquake data: {e}{Style.RESET_ALL}")
    
    pause()

# Disable SSL warnings for PHIVOLCS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_phivolcs_html():
    """
    Fetch and display earthquake data from PHIVOLCS website
    Gets data from the main earthquake bulletin page
    """
    print("\n🇵🇭 PHIVOLCS LATEST EARTHQUAKE INFORMATION")
    print("=" * 100)
    
    url = "https://earthquake.phivolcs.dost.gov.ph/"
    
    try:
        # Set headers to mimic browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        print("🔄 Fetching data from PHIVOLCS...")
        
        # Fetch the webpage
        response = requests.get(url, headers=headers, timeout=20, verify=False)
        response.raise_for_status()
        
        # Parse HTML
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Try multiple methods to find the table
        table = None
        
        # Method 1: Find table by ID
        table = soup.find('table', {'id': 'earthquake_table'})
        
        # Method 2: Find table by class
        if not table:
            table = soup.find('table', {'class': 'table'})
        
        # Method 3: Find all tables and get the one with earthquake data
        if not table:
            tables = soup.find_all('table')
            for t in tables:
                # Check if table has typical earthquake headers
                headers_text = t.get_text().lower()
                if any(word in headers_text for word in ['magnitude', 'latitude', 'longitude', 'depth']):
                    table = t
                    break
        
        # Method 4: Try finding tbody directly
        if not table:
            tbody = soup.find('tbody')
            if tbody:
                table = tbody.parent
        
        if not table:
            print("❌ Could not find earthquake data table on PHIVOLCS website")
            print("   The website may be down or structure has changed.")
            print(f"\n💡 Alternative: Visit {url} directly in your browser")
            pause()
            return
        
        earthquake_data = []
        
        # Parse table rows
        table_rows = table.find_all('tr')
        
        # Skip header row(s)
        data_rows = [tr for tr in table_rows if len(tr.find_all('td')) > 0]
        
        print(f"✅ Found {len(data_rows)} earthquake records\n")
        
        # Get up to 30 most recent earthquakes
        for idx, tr in enumerate(data_rows[:50]):
            cols = tr.find_all('td')
            
            if len(cols) >= 5:
                try:
                    # Extract RAW text data (strip all HTML and formatting)
                    date_time = cols[0].get_text(strip=True)
                    latitude = cols[1].get_text(strip=True)
                    longitude = cols[2].get_text(strip=True)
                    depth_raw = cols[3].get_text(strip=True)
                    magnitude_raw = cols[4].get_text(strip=True)
                    
                    # Debug: Print first row to see what we're getting
                    if idx == 0:
                        print(f"✓ Successfully parsing data...")
                        print()
                    
                    # Try to get location if available
                    location = "N/A"
                    if len(cols) > 5:
                        location = cols[5].get_text(strip=True)
                        location = re.sub(r'\s+', ' ', location)
                    
                    # Parse magnitude as float
                    mag_float = 0.0
                    try:
                        # Remove any non-numeric characters except decimal point and minus
                        mag_clean = re.sub(r'[^\d.\-]', '', magnitude_raw)
                        if mag_clean and mag_clean not in ['.', '-', '-.']:
                            mag_float = float(mag_clean)
                    except ValueError:
                        mag_float = 0.0
                    
                    # Parse depth as float
                    depth_float = 0.0
                    try:
                        # Extract first number from depth string
                        depth_match = re.findall(r'\d+\.?\d*', depth_raw)
                        if depth_match:
                            depth_float = float(depth_match[0])
                    except ValueError:
                        depth_float = 0.0
                    
                    # Clean date/time
                    date_time = re.sub(r'\s+', ' ', date_time)
                    
                    # Store raw data for later formatting
                    earthquake_data.append({
                        'datetime': date_time,
                        'latitude': latitude,
                        'longitude': longitude,
                        'depth': depth_float,
                        'magnitude': mag_float,
                        'location': location[:50]
                    })
                    
                except Exception as e:
                    # Skip malformed rows
                    continue
        
        if earthquake_data:
            # Now format for display
            display_rows = []
            for eq in earthquake_data:
                # Color code magnitude
                if eq['magnitude'] >= 5.0:
                    mag_str = f"{Style.BRIGHT}{Fore.RED}{eq['magnitude']:.1f}{Style.RESET_ALL}"
                elif eq['magnitude'] >= 3.0:
                    mag_str = f"{Style.BRIGHT}{Fore.YELLOW}{eq['magnitude']:.1f}{Style.RESET_ALL}"
                else:
                    mag_str = f"{Style.BRIGHT}{Fore.GREEN}{eq['magnitude']:.1f}{Style.RESET_ALL}"
                
                # Color code depth
                if eq['depth'] <= 70:
                    depth_str = f"{Fore.RED}{eq['depth']:.0f} km{Style.RESET_ALL}"
                elif eq['depth'] <= 300:
                    depth_str = f"{Fore.YELLOW}{eq['depth']:.0f} km{Style.RESET_ALL}"
                else:
                    depth_str = f"{Fore.CYAN}{eq['depth']:.0f} km{Style.RESET_ALL}"
                
                display_rows.append([
                    eq['datetime'],
                    eq['latitude'],
                    eq['longitude'],
                    depth_str,
                    mag_str,
                    eq['location']
                ])
            
            print(f"📊 Displaying Latest {len(display_rows)} Earthquakes (Sorted by Most Recent)\n")
            
            print(tabulate(
                display_rows,
                headers=["Date & Time (PST)", "Lat", "Lon", "Depth", "Mag", "Location"],
                tablefmt="fancy_grid",
                maxcolwidths=[20, 10, 10, 12, 8, 50],
                disable_numparse=True
            ))
            
            # Calculate and display summary statistics
            print(f"\n" + "="*100)
            print(f"📈 SUMMARY STATISTICS")
            print("="*100)
            
            # Extract magnitudes and depths for statistics
            mags = [eq['magnitude'] for eq in earthquake_data if eq['magnitude'] > 0]
            depths = [eq['depth'] for eq in earthquake_data if eq['depth'] > 0]
            
            if mags:
                # Magnitude statistics
                strong = sum(1 for m in mags if m >= 5.0)
                moderate = sum(1 for m in mags if 3.0 <= m < 5.0)
                weak = sum(1 for m in mags if m < 3.0)
                max_mag = max(mags)
                avg_mag = sum(mags) / len(mags)
                
                print(f"\n🔢 Total Earthquakes: {len(earthquake_data)}")
                print(f"\n📏 Magnitude Distribution:")
                print(f"   {Fore.RED}● Strong (M ≥ 5.0):{Style.RESET_ALL} {strong} earthquake(s)")
                print(f"   {Fore.YELLOW}● Moderate (3.0 ≤ M < 5.0):{Style.RESET_ALL} {moderate} earthquake(s)")
                print(f"   {Fore.GREEN}● Weak (M < 3.0):{Style.RESET_ALL} {weak} earthquake(s)")
                print(f"\n📊 Statistics:")
                print(f"   Strongest: {Fore.RED}M {max_mag:.1f}{Style.RESET_ALL}")
                print(f"   Average Magnitude: M {avg_mag:.1f}")
                
                if depths:
                    avg_depth = sum(depths) / len(depths)
                    max_depth = max(depths)
                    min_depth = min(depths)
                    print(f"   Average Depth: {avg_depth:.1f} km")
                    print(f"   Depth Range: {min_depth:.1f} - {max_depth:.1f} km")
            
            print(f"\n" + "="*100)
            print(f"💡 LEGEND:")
            print(f"   Magnitude: {Fore.RED}Strong ≥5.0{Style.RESET_ALL} | {Fore.YELLOW}Moderate 3.0-4.9{Style.RESET_ALL} | {Fore.GREEN}Weak <3.0{Style.RESET_ALL}")
            print(f"   Depth: {Fore.RED}Shallow ≤70km{Style.RESET_ALL} | {Fore.YELLOW}Intermediate 70-300km{Style.RESET_ALL} | {Fore.CYAN}Deep >300km{Style.RESET_ALL}")
            print(f"\n🌐 Data Source: PHIVOLCS (Philippine Institute of Volcanology and Seismology)")
            print(f"⏰ Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S PST')}")
            print("="*100)
            
        else:
            print("⚠️ No earthquake data could be parsed from the website.")
            print(f"   Please visit {url} to check manually.")
            
    except requests.exceptions.SSLError:
        print(f"❌ SSL Certificate error accessing PHIVOLCS website.")
        print(f"   This is a known issue with the PHIVOLCS server.")
    except requests.exceptions.Timeout:
        print(f"❌ Connection timeout. PHIVOLCS server may be slow or down.")
        print(f"   Please try again later.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error: {e}")
        print(f"   Please check your internet connection.")
    except Exception as e:
        print(f"❌ Error: {e}")
        print(f"   The website structure may have changed.")
        print(f"\n💡 Visit {url} directly for latest information")
    
    pause()

# =============================================================================
# GENERIC WEB SCRAPER
# =============================================================================

def get_generic_scrape():
    """Interactive web scraper"""
    print_header("🔍 Generic Web Scraper")
    
    print(f"{Fore.CYAN}How to use:{Style.RESET_ALL}")
    print("1. Visit target website in browser")
    print("2. Right-click element → Inspect")
    print("3. Right-click highlighted code → Copy → Copy selector")
    print("4. Paste selector here\n")
    print(f"{Fore.YELLOW}Commands: 'menu' (clear), 'new' (again), 'exit' (quit){Style.RESET_ALL}\n")
    
    while True:
        url = input(f"\n{Fore.GREEN}Enter URL (or 'exit'): {Style.RESET_ALL}").strip()
        
        if url.lower() == 'exit':
            break
        
        if not url.startswith(('http://', 'https://')):
            print(f"{Fore.RED}Invalid URL format{Style.RESET_ALL}")
            continue
        
        selector = input(f"{Fore.GREEN}Enter CSS selector: {Style.RESET_ALL}").strip()
        if not selector:
            print(f"{Fore.RED}Selector required{Style.RESET_ALL}")
            continue
        
        limit_input = input(f"{Fore.GREEN}Limit (blank for all): {Style.RESET_ALL}").strip()
        limit = int(limit_input) if limit_input.isdigit() else None
        
        print(f"\n{Fore.CYAN}Scraping {url}...{Style.RESET_ALL}")
        
        response = safe_request(url)
        if not response:
            continue
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            elements = soup.select(selector)
            
            if not elements:
                print(f"{Fore.YELLOW}No elements found{Style.RESET_ALL}")
                continue
            
            if limit:
                elements = elements[:limit]
            
            print(f"\n{Fore.GREEN}Found {len(elements)} elements:{Style.RESET_ALL}\n")
            
            for i, element in enumerate(elements, 1):
                text = element.get_text(strip=True)
                text = re.sub(r'\s+', ' ', text).strip()
                link = element.get('href', '')
                
                print(f"{Fore.CYAN}[{i}]{Style.RESET_ALL} {text[:100]}")
                if link and link.startswith(('http', '/')):
                    print(f"    {Fore.LIGHTBLACK_EX}→ {link}{Style.RESET_ALL}")
                print()
        
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.YELLOW}Continue? (new/menu/exit): {Style.RESET_ALL}").strip().lower()
        if choice == 'menu':
            clear_screen()
        elif choice == 'exit':
            break

# =============================================================================
# BROWSER OPENERS (Cross-Platform)
# =============================================================================

def open_browser_termux(url: str) -> bool:
    """
    Open browser - works on both Termux and desktop
    Returns True if successful
    """
    if IS_TERMUX:
        # Method 1: termux-open-url (best for Termux)
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
                'am', 'start', '--user', '0',
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
            return webbrowser.open(url)
        except:
            return False

def open_in_browser(url, name):
    """Open URL in browser with cross-platform support"""
    print(f"\n{Fore.CYAN}Opening {name}...{Style.RESET_ALL}")
    
    success = open_browser_termux(url)
    
    if success:
        print(f"{Fore.GREEN}✓ Opened successfully{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}⚠️ Could not auto-open browser{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Please visit manually: {url}{Style.RESET_ALL}")
    
    pause()

def open_pagasa():
    open_in_browser("https://panahon.gov.ph", "PAGASA Weather")

def open_pimoh_weather():
    open_in_browser("https://www.pimohweather.com/wxTyphoonSector.php", "Pimoh Weather")

# =============================================================================
# MAIN MENU
# =============================================================================

def display_system_info():
    """Display system information"""
    print(f"\n{Fore.CYAN}System: {Style.RESET_ALL}{platform.system()} {platform.release()}")
    if IS_TERMUX:
        print(f"{Fore.CYAN}Platform: {Style.RESET_ALL}Termux (Android)")
    elif IS_ANDROID:
        print(f"{Fore.CYAN}Platform: {Style.RESET_ALL}Android")
    print(f"{Fore.CYAN}Python: {Style.RESET_ALL}{sys.version.split()[0]}")
    print(f"{Fore.CYAN}Created By: {Style.RESET_ALL}Frank Net Tools")

def main_menu():
    """Main menu loop"""
    while True:
        clear_screen()
        print_header("🌐 Web Scraper & Information Tool")
        
        display_system_info()
        
        print(f"\n{Fore.YELLOW}{'═' * 80}{Style.RESET_ALL}")
        print(f"{Fore.GREEN} 1.{Style.RESET_ALL}  Global Technology News")
        print(f"{Fore.GREEN} 2.{Style.RESET_ALL}  TechCrunch News")
        print(f"{Fore.GREEN} 3.{Style.RESET_ALL}  Microsoft Tech News")
        print(f"{Fore.GREEN} 4.{Style.RESET_ALL}  Philippines News (RSS)")
        print(f"{Fore.GREEN} 5.{Style.RESET_ALL}  Philippines News (Rappler)")
        print(f"{Fore.GREEN} 6.{Style.RESET_ALL}  Global News Headlines")
        print(f"{Fore.GREEN} 7.{Style.RESET_ALL}  Philippines Weather Dashboard")
        print(f"{Fore.GREEN} 8.{Style.RESET_ALL}  Currency Exchange Rates")
        print(f"{Fore.GREEN} 9.{Style.RESET_ALL}  USGS Earthquake Data")
        print(f"{Fore.GREEN}10.{Style.RESET_ALL}  PHIVOLCS Earthquake Data")
        print(f"{Fore.GREEN}11.{Style.RESET_ALL}  PHIVOLCS Tsunami Alerts")
        print(f"{Fore.GREEN}12.{Style.RESET_ALL}  Open PAGASA Weather (Browser)")
        print(f"{Fore.GREEN}13.{Style.RESET_ALL}  Open Pimoh Weather (Browser)")
        print(f"{Fore.GREEN}14.{Style.RESET_ALL}  Generic Web Scraper")
        print(f"{Fore.GREEN} 0.{Style.RESET_ALL}  Exit")
        print(f"{Fore.YELLOW}{'═' * 80}{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.CYAN}Select option (0-14): {Style.RESET_ALL}").strip()
        
        if choice == '1':
            clear_screen()
            get_global_tech_news()
        elif choice == '2':
            clear_screen()
            get_tech_news()
        elif choice == '3':
            clear_screen()
            get_microsoft_news()
        elif choice == '4':
            clear_screen()
            get_philippines_news()
        elif choice == '5':
            clear_screen()
            get_ph_news()
        elif choice == '6':
            clear_screen()
            get_global_news()
        elif choice == '7':
            clear_screen()
            get_philippines_weather()
        elif choice == '8':
            clear_screen()
            get_currency_rate()
        elif choice == '9':
            clear_screen()
            fetch_earthquake()
        elif choice == '10':
            clear_screen()
            fetch_phivolcs_html()
        elif choice == '11':
            clear_screen()
            fetch_tsunami()
        elif choice == '12':
            open_pagasa()
        elif choice == '13':
            open_pimoh_weather()
        elif choice == '14':
            clear_screen()
            get_generic_scrape()
        elif choice == '0':
            print(f"\n{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
            time.sleep(1)

# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Program interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)
