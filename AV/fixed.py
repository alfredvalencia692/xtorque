#!/usr/bin/env python3
"""
Automatic Comprehensive Fixer for frank-av3.py
Applies ALL 7 fixes automatically

Usage:
    python3 auto_fix_frank_av3.py frank-av3.py

This will:
1. Create backup (frank-av3.py.backup)
2. Apply all fixes
3. Create fixed version (frank-av3-FIXED.py)
"""

import sys
import re
import os

def apply_all_fixes(content):
    """Apply all 7 fixes to the script content"""
    
    print("Applying Fix 1: Set path to /root/projectx/root/xtorque/AV/...")
    # Fix 1: Replace SCRIPT_DIR setup
    content = re.sub(
        r'# Auto-detect script directory\nSCRIPT_DIR = os\.path\.dirname\(os\.path\.abspath\(__file__\)\)',
        '# FIXED PATH - All data stored here\nSCRIPT_DIR = "/root/projectx/root/xtorque/AV"\n\n# Create directory if it doesn\'t exist\nos.makedirs(SCRIPT_DIR, exist_ok=True)',
        content
    )
    
    # Remove old custom path logic
    content = re.sub(
        r'# If user wants specific paths.*?SCRIPT_DIR = CUSTOM_PATH_3\n',
        '# All files stored in /root/projectx/root/xtorque/AV/\n',
        content,
        flags=re.DOTALL
    )
    
    print("Applying Fix 2: Move DB_PATH to database/...")
    # Fix 2: Move DB_PATH
    content = content.replace(
        'DB_PATH = os.path.join(SCRIPT_DIR, "malware_hashes.db")',
        'DB_PATH = os.path.join(SCRIPT_DIR, "database", "malware_hashes.db")'
    )
    
    print("Applying Fix 3: Move RESUME_FILE to config/...")
    # Fix 3: Move RESUME_FILE
    content = content.replace(
        'RESUME_FILE = os.path.join(SCRIPT_DIR, "vt_resume.json")',
        'RESUME_FILE = os.path.join(SCRIPT_DIR, "config", "vt_resume.json")'
    )
    
    print("Applying Fix 4: Add startup stats function...")
    # Fix 4: Add show_startup_stats function before main_menu
    startup_stats_function = '''
def show_startup_stats():
    """Display database statistics on startup."""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM hashes")
            total = cursor.fetchone()[0]
            conn.close()
            
            print(f"{Colors.OKBLUE}📊 Malware Database: {Colors.OKGREEN}{total:,} signatures loaded{Colors.ENDC}")
            log_event(f"Startup: {total} signatures in database", "INFO")
        except:
            print(f"{Colors.WARNING}⚠️  Database check failed{Colors.ENDC}")
            if conn:
                conn.close()
    print()

'''
    
    # Insert before main_menu
    content = content.replace(
        'def main_menu():',
        startup_stats_function + 'def main_menu():'
    )
    
    # Call it in __main__
    content = content.replace(
        '        # Check auto-updates\n        check_auto_updates() \n        \n        # Start menu\n        main_menu()',
        '        # Check auto-updates\n        check_auto_updates() \n        \n        # Show database stats on startup\n        show_startup_stats()\n        \n        # Start menu\n        main_menu()'
    )
    
    print("Applying Fix 5: Fix browser auto-open prompt...")
    # Fix 5: Fix browser prompt in start_web_dashboard
    old_browser_section = r'''        print\(f"\\n{Colors\.WARNING}⚠️  Press Ctrl\+C to stop the dashboard{Colors\.ENDC}\\n"\)
        
        # Auto-open browser
        if auto_open:
            print\(f"{Colors\.OKBLUE}🚀 Opening browser\.\.\.{Colors\.ENDC}"\)
            import threading
            url = f"http://localhost:{port}"
            threading\.Thread\(target=open_browser, args=\(url,\), daemon=True\)\.start\(\)
        
        try:'''
    
    new_browser_section = '''        # Auto-open browser with prompt
        if auto_open:
            try:
                browser_choice = input(f"{Colors.OKCYAN}🌐 Open browser automatically? (Y/n): {Colors.ENDC}").strip().lower()
                if browser_choice != 'n':
                    print(f"{Colors.OKBLUE}🚀 Opening browser...{Colors.ENDC}")
                    import threading
                    url = f"http://localhost:{port}"
                    threading.Thread(target=open_browser, args=(url,), daemon=True).start()
                    time.sleep(2)
                else:
                    print(f"{Colors.OKCYAN}💡 Manually open: http://localhost:{port}{Colors.ENDC}")
            except:
                pass
        
        print(f"\\n{Colors.WARNING}⚠️  Press Ctrl+C to stop the dashboard{Colors.ENDC}\\n")
        
        try:'''
    
    content = re.sub(old_browser_section, new_browser_section, content, flags=re.DOTALL)
    
    print("Applying Fix 6 & 7: Improve browser opening for Ubuntu...")
    # Fix 6 & 7: Replace open_browser function
    old_open_browser = r'''    def open_browser\(url, delay=2\):
        """Open browser with delay\."""
        import time
        time\.sleep\(delay\)
        try:
            # For Termux, use termux-open-url if available
            if IS_TERMUX:
                try:
                    subprocess\.run\(\['termux-open-url', url\], check=True\)
                    return
                except:
                    pass
            
            # Fallback to Python's webbrowser
            webbrowser\.open\(url\)
        except Exception as e:
            print\(f"{Colors\.WARNING}Could not auto-open browser: {e}{Colors\.ENDC}"\)'''
    
    new_open_browser = '''    def open_browser(url, delay=1):
        """Open browser with delay - Ubuntu optimized."""
        import time
        time.sleep(delay)
        
        print(f"{Colors.OKBLUE}🔍 Attempting to open browser...{Colors.ENDC}")
        
        # Try multiple methods for Ubuntu/Linux
        methods = [
            (['xdg-open', url], 'xdg-open'),
            (['sensible-browser', url], 'sensible-browser'),
            (['x-www-browser', url], 'x-www-browser'),
            (['firefox', url], 'firefox'),
            (['google-chrome', url], 'chrome'),
            (['chromium-browser', url], 'chromium'),
        ]
        
        for cmd, name in methods:
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=3)
                if result.returncode == 0:
                    print(f"{Colors.OKGREEN}✅ Opened with {name}{Colors.ENDC}")
                    return True
            except:
                continue
        
        # Fallback to Python's webbrowser
        try:
            webbrowser.open(url)
            print(f"{Colors.OKGREEN}✅ Browser opened{Colors.ENDC}")
            return True
        except Exception as e:
            print(f"{Colors.WARNING}⚠️  Could not auto-open browser{Colors.ENDC}")
            print(f"{Colors.OKCYAN}💡 Please manually open: {url}{Colors.ENDC}")
            return False'''
    
    content = re.sub(old_open_browser, new_open_browser, content, flags=re.DOTALL)
    
    print("✅ All fixes applied!")
    return content

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 auto_fix_frank_av3.py frank-av3.py")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found!")
        sys.exit(1)
    
    print(f"{'='*60}")
    print(f"Auto-Fixer for Frankenstein AV")
    print(f"{'='*60}")
    print(f"Input file: {input_file}")
    print(f"")
    
    # Read original
    with open(input_file, 'r', encoding='utf-8') as f:
        original_content = f.read()
    
    print(f"Original file size: {len(original_content)} characters")
    print(f"")
    
    # Create backup
    backup_file = f"{input_file}.backup"
    with open(backup_file, 'w', encoding='utf-8') as f:
        f.write(original_content)
    print(f"✅ Backup created: {backup_file}")
    print(f"")
    
    # Apply fixes
    fixed_content = apply_all_fixes(original_content)
    
    # Write fixed version
    output_file = f"{input_file.replace('.py', '')}-FIXED.py"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(fixed_content)
    
    print(f"")
    print(f"{'='*60}")
    print(f"✅ DONE!")
    print(f"{'='*60}")
    print(f"Fixed file created: {output_file}")
    print(f"Backup saved: {backup_file}")
    print(f"")
    print(f"Test it:")
    print(f"  cd /root/projectx/root/xtorque/")
    print(f"  python3 {output_file}")
    print(f"")
    print(f"Expected to see:")
    print(f"  📊 Malware Database: X signatures loaded")
    print(f"  🌐 Browser prompt when using web dashboard")
    print(f"  All data in: /root/projectx/root/xtorque/AV/")
    print(f"")

if __name__ == "__main__":
    main()