import sys
import os
import time
import hashlib
import getpass
import base64
import json
import mimetypes
from datetime import datetime
from pathlib import Path
import platform

# Check if running on Windows, Linux, or Termux
IS_WINDOWS = platform.system() == 'Windows'
IS_TERMUX = os.path.exists('/data/data/com.termux')

# Conditionally import Windows-specific modules
if IS_WINDOWS:
    try:
        import msvcrt
        import winsound
    except ImportError:
        pass

# Import cross-platform compatible modules
try:
    import google.generativeai as genai
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text
    from cryptography.fernet import Fernet, InvalidToken
    import pyperclip
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Install with: pip install google-generativeai rich cryptography pyperclip")
    sys.exit(1)

# Try to import reportlab, but make it optional
try:
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Get the base directory where the script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Load environment variables
def load_env():
    """Load .env file from script directory."""
    env_path = os.path.join(SCRIPT_DIR, '.env')
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip().strip('"').strip("'")
    else:
        print(f"Warning: .env file not found at {env_path}")

load_env()
console = Console()

# Configuration
GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY")
GEMINI_MODEL = "gemini-2.0-flash-exp"

# Create all directories relative to script location
gemini_chat_dir = os.path.join(SCRIPT_DIR, "gemini_chats")
gemini_export_dir = os.path.join(SCRIPT_DIR, "gemini_exports")
kali_sage_chat_dir = os.path.join(SCRIPT_DIR, "kali_sage_chats")
kali_sage_export_dir = os.path.join(SCRIPT_DIR, "kali_sage_exports")

# Create necessary directories
os.makedirs(gemini_chat_dir, exist_ok=True)
os.makedirs(gemini_export_dir, exist_ok=True)
os.makedirs(kali_sage_chat_dir, exist_ok=True)
os.makedirs(kali_sage_export_dir, exist_ok=True)

# Configure Gemini API
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    console.print("[red]Warning: GOOGLE_API_KEY not found. Get your free key at: https://aistudio.google.com/apikey[/red]")
    sys.exit(1)

# Kali Sage Configuration
KALI_SAGE_MODEL = "gemini-2.0-flash-exp"

# Kali Sage Persona
KALI_SAGE_PERSONA = """You are Kali Sage — an elite AI expert in Kali Linux, cybersecurity, penetration testing, and ethical hacking.

Your Expertise:
- Kali Linux tools and commands (nmap, metasploit, burpsuite, wireshark, aircrack-ng, john, hashcat, etc.)
- Network security and penetration testing methodologies
- Web application security (OWASP Top 10, SQL injection, XSS, CSRF)
- Cryptography and secure communications
- Exploit development and vulnerability assessment
- Digital forensics and incident response
- Python/Bash scripting for security automation
- Wireless security and social engineering techniques

Your Response Style:
- Provide accurate, practical command-line examples with explanations
- Explain the reasoning and methodology behind each technique
- Include security best practices and warnings about detection
- Use clear, concise technical language
- Always emphasize LEGAL and ETHICAL use only
- Warn about potential risks, consequences, and legal implications
- Provide step-by-step instructions when relevant

Your Ethics:
- Only assist with authorized, legal security testing
- Always remind users to obtain proper written authorization
- Refuse requests for malicious or illegal activities
- Promote responsible disclosure of vulnerabilities
- Emphasize learning for defensive security purposes
- Remind users that unauthorized access is a crime

Remember: All advice is for educational purposes and authorized security testing only. Unauthorized access to systems is illegal and unethical."""

def clear_screen():
    """Cross-platform screen clear."""
    os.system("cls" if IS_WINDOWS else "clear")

def _hex_to_rgb(hex_color: str):
    """Convert hex color to RGB tuple."""
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))

def multiline_input(prompt_text="[bold green]You:[/bold green]"):
    """Multi-line input: type END on a new line to finish."""
    console.print(Text.from_markup(prompt_text), end=" ")
    buffer = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "END":
            break
        buffer.append(line)
    return "\n".join(buffer)

def derive_key(password):
    """Derive encryption key from password."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_data(data, password):
    """Encrypt data with password."""
    f = Fernet(derive_key(password))
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(data, password):
    """Decrypt data with password."""
    f = Fernet(derive_key(password))
    return json.loads(f.decrypt(data).decode())

def timestamp():
    """Return current timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ============= GEMINI FUNCTIONS =============

def gemini_display_title():
    """Display Gemini banner with gradient."""
    banner = """
██╗       ██████╗ ███████╗███╗   ███╗██╗███╗   ██╗██╗
╚██╗     ██╔════╝ ██╔════╝████╗ ████║██║████╗  ██║██║
 ╚██╗    ██║  ███╗█████╗  ██╔████╔██║██║██╔██╗ ██║██║
 ██╔╝    ██║   ██║██╔══╝  ██║╚██╔╝██║██║██║╚██╗██║██║
██╔╝     ╚██████╔╝███████╗██║ ╚═╝ ██║██║██║ ╚████║██║
╚═╝       ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝
                                                                                                                                                                                                                                                                                                                   
            GEMINI AI TERMINAL CHAT
"""
    colors = ["#9933FF", "#3366FF", "#FF00FF"]
    rgb_colors = [_hex_to_rgb(c) for c in colors]

    chars = list(banner)
    visible_positions = [i for i, ch in enumerate(chars) if ch != "\n"]
    total = len(visible_positions)

    text = Text()
    used = 0
    for ch in chars:
        if ch == "\n":
            text.append("\n")
            continue

        ratio = used / (total - 1) if total > 1 else 0.0

        if ratio <= 0.5:
            seg_ratio = ratio / 0.5
            c1, c2 = rgb_colors[0], rgb_colors[1]
        else:
            seg_ratio = (ratio - 0.5) / 0.5
            c1, c2 = rgb_colors[1], rgb_colors[2]

        r = int(c1[0] + (c2[0] - c1[0]) * seg_ratio)
        g = int(c1[1] + (c2[1] - c1[1]) * seg_ratio)
        b = int(c1[2] + (c2[2] - c1[2]) * seg_ratio)
        color = f"#{r:02x}{g:02x}{b:02x}"

        text.append(ch, style=f"bold {color}")
        used += 1

    console.print(text)

# ============= KALI SAGE FUNCTIONS =============

def kali_sage_display_title():
    """Display Kali Sage banner with gradient."""
    banner = """
██╗      ██╗  ██╗ █████╗ ██╗     ██╗    ███████╗ █████╗  ██████╗ ███████╗
╚██╗     ██║ ██╔╝██╔══██╗██║     ██║    ██╔════╝██╔══██╗██╔════╝ ██╔════╝
 ╚██╗    █████╔╝ ███████║██║     ██║    ███████╗███████║██║  ███╗█████╗  
 ██╔╝    ██╔═██╗ ██╔══██║██║     ██║    ╚════██║██╔══██║██║   ██║██╔══╝  
██╔╝     ██║  ██╗██║  ██║███████╗██║    ███████║██║  ██║╚██████╔╝███████╗
╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝    ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝                                                                     
                                                                                                               
                    KALI SAGE AI TERMINAL CHAT
                Ethical Hacking - Cybersecurity Expert
"""
    colors = ["#EE1D01", "#5F33FF", "#0099FF"]
    rgb_colors = [_hex_to_rgb(c) for c in colors]

    chars = list(banner)
    visible_positions = [i for i, ch in enumerate(chars) if ch != "\n"]
    total = len(visible_positions)

    text = Text()
    used = 0
    for ch in chars:
        if ch == "\n":
            text.append("\n")
            continue

        ratio = used / (total - 1) if total > 1 else 0.0

        if ratio <= 0.5:
            seg_ratio = ratio / 0.5
            c1, c2 = rgb_colors[0], rgb_colors[1]
        else:
            seg_ratio = (ratio - 0.5) / 0.5
            c1, c2 = rgb_colors[1], rgb_colors[2]

        r = int(c1[0] + (c2[0] - c1[0]) * seg_ratio)
        g = int(c1[1] + (c2[1] - c1[1]) * seg_ratio)
        b = int(c1[2] + (c2[2] - c1[2]) * seg_ratio)
        color = f"#{r:02x}{g:02x}{b:02x}"

        text.append(ch, style=f"bold {color}")
        used += 1

    console.print(text)

# ============= SHARED FUNCTIONS =============

def get_session_path(name, chat_dir):
    """Get session file path."""
    os.makedirs(chat_dir, exist_ok=True)
    return os.path.join(chat_dir, f"{name}.chat")

def save_chat(name, history, password, chat_dir):
    """Save encrypted chat."""
    encrypted = encrypt_data(history, password)
    with open(get_session_path(name, chat_dir), "wb") as f:
        f.write(encrypted)

def load_chat(name, password, chat_dir):
    """Load encrypted chat."""
    try:
        with open(get_session_path(name, chat_dir), "rb") as f:
            encrypted = f.read()
        return decrypt_data(encrypted, password)
    except (FileNotFoundError, InvalidToken):
        console.print("[red]Failed to load or decrypt session.[/red]")
        return None

def export_chat(session, history, export_dir):
    """Export chat as MD and TXT (PDF optional)."""
    os.makedirs(export_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(export_dir, session)
    md = f"{base}_{ts}.md"
    txt = f"{base}_{ts}.txt"

    # Export MD and TXT
    with open(md, "w", encoding="utf-8") as f_md, open(txt, "w", encoding="utf-8") as f_txt:
        for entry in history:
            if entry.get("role") != "image":
                line = f"{entry['timestamp']} - {entry['role'].capitalize()}: {entry['message']}\n"
                f_md.write(line)
                f_txt.write(line)

    console.print(f"[green]Exported as:[/green]\n- {md}\n- {txt}")

    # Export PDF if reportlab is available
    if REPORTLAB_AVAILABLE:
        pdf = f"{base}_{ts}.pdf"
        try:
            doc = SimpleDocTemplate(pdf)
            styles = getSampleStyleSheet()
            content = []
            for e in history:
                if e.get("role") != "image":
                    content.append(
                        Paragraph(
                            f"{e['timestamp']} [{e['role'].capitalize()}] {e['message'][:500]}",
                            styles["Normal"],
                        )
                    )
                    content.append(Spacer(1, 12))
            doc.build(content)
            console.print(f"- {pdf}")
        except Exception as e:
            console.print(f"[yellow]PDF export failed: {e}[/yellow]")

def show_help():
    """Show help menu."""
    console.print(
        Markdown(
            """[bold cyan]
## Available Commands

- `copy`         : Copy last response
- `retry`        : Retry a previous user message
- `summarize`    : Summarize the conversation
- `lookup`       : Search chat history
- `history`      : Load and display history
- `export`       : Export chat as MD, TXT (and PDF if available)
- `new`          : Start a new chat session
- `load`         : Load another saved session
- `help`         : Show help commands
- `exit`/`quit`  : Save and exit
[/bold cyan]"""
        )
    )

def display_history(history, page_size=100):
    """Display chat history with pagination."""
    if not history:
        console.print("[yellow]No chat history to display.[/yellow]")
        return

    total_messages = len(history)
    total_pages = (total_messages + page_size - 1) // page_size
    current_page = total_pages

    while True:
        start_idx = (current_page - 1) * page_size
        end_idx = min(start_idx + page_size, total_messages)
        page_messages = history[start_idx:end_idx]

        console.print("─" * 60)
        console.print(f"[bold green]Chat History (Page {current_page} of {total_pages})[/bold green]")
        console.print("─" * 60)

        for msg in page_messages:
            timestamp_str = msg.get("timestamp", "")
            role_str = msg.get("role", "").capitalize()
            message_str = msg.get("message", "")

            if role_str.lower() in ["user", "model"]:
                console.print(f"[{timestamp_str}] [green]{role_str}[/green]: {message_str}")
            elif role_str.lower() == "image":
                console.print(f"[{timestamp_str}] [cyan]{role_str}[/cyan]: {message_str}")

        if total_pages <= 1:
            break

        console.print("─" * 60)
        command = Prompt.ask("[cyan]Commands: [P]revious, [N]ext, [Q]uit[/cyan]").strip().lower()

        if command == "n":
            if current_page < total_pages:
                current_page += 1
            else:
                console.print("[yellow]Already at the newest page.[/yellow]")
        elif command == "p":
            if current_page > 1:
                current_page -= 1
            else:
                console.print("[yellow]Already at the oldest page.[/yellow]")
        elif command == "q":
            break
        else:
            console.print("[red]Invalid command. Use P, N, or Q.[/red]")

def session_menu(chat_dir, title="Session Menu"):
    """Generic session menu."""
    console.print("=======================================================")
    console.print(f"[bold cyan]{title}[/bold cyan]")
    console.print("1. New Chat Session")
    console.print("2. Load Chat Session")
    console.print("=======================================================")
    choice = Prompt.ask("Choose", choices=["1", "2"])

    if choice == "1":
        name = Prompt.ask("Enter session name")
        password = getpass.getpass("Set password: ")
        return name, password
    else:
        sessions = []
        for root, _, files in os.walk(chat_dir):
            for f in files:
                if f.endswith(".chat"):
                    sessions.append(os.path.relpath(os.path.join(root, f), chat_dir))
        
        if not sessions:
            console.print(f"[red]No saved sessions in {chat_dir}.[/red]")
            return None, None
        
        table = Table(title="Saved Sessions")
        table.add_column("Index")
        table.add_column("Session File")
        for i, s in enumerate(sessions):
            table.add_row(str(i), s)
        console.print(table)
        
        idx = int(Prompt.ask("Choose session index"))
        selected = sessions[idx].replace("\\", "/")
        name = os.path.splitext(os.path.basename(selected))[0]
        password = getpass.getpass("Enter password: ")
        return name, password

def start_chat(session_name, password, model_name, chat_dir, export_dir, persona=None, title="AI"):
    """Generic chat session handler."""
    history = load_chat(session_name, password, chat_dir) or []

    if history:
        display_history(history)

    model = genai.GenerativeModel(model_name)
    
    chat_history_for_model = [
        {"role": h["role"], "parts": [h["message"]]}
        for h in history
        if h.get("message") and h["role"] in ["user", "model"]
    ]
    
    if persona and not chat_history_for_model:
        chat_history_for_model = [
            {"role": "user", "parts": [persona]},
            {"role": "model", "parts": [f"Understood. I am {title}, ready to assist."]}
        ]
    
    chat = model.start_chat(history=chat_history_for_model)

    while True:
        user_input = multiline_input()
        if not user_input.strip():
            console.print("[red]Please enter a prompt or command.[/red]")
            continue

        if user_input.lower() in ["exit", "quit"]:
            save_chat(session_name, history, password, chat_dir)
            console.print(f"[green]{title} session saved![/green]")
            break

        elif user_input.lower() == "help":
            show_help()

        elif user_input.lower() == "copy":
            if history:
                last_msg = next((h["message"] for h in reversed(history) if h.get("message") and h["role"] == "model"), "")
                try:
                    pyperclip.copy(last_msg)
                    console.print("[green]✓ Copied to clipboard![/green]")
                except Exception as e:
                    console.print(f"[yellow]Clipboard not available: {e}[/yellow]")
            else:
                console.print("[yellow]No messages to copy.[/yellow]")

        elif user_input.lower() == "export":
            export_chat(session_name, history, export_dir)

        elif user_input.lower() == "history":
            history = load_chat(session_name, password, chat_dir) or []
            display_history(history)

        elif user_input.lower() == "summarize":
            summary_prompt = "Summarize our conversation so far."
            history.append({"role": "user", "message": summary_prompt, "timestamp": timestamp()})
            
            with console.status("[bold yellow]⚡ Analyzing...[/bold yellow]"):
                try:
                    response = chat.send_message(summary_prompt)
                    reply = "".join(part.text for part in response.candidates[0].content.parts if hasattr(part, "text"))
                except Exception as e:
                    reply = f"[Error: {e}]"

            history.append({"role": "model", "message": reply, "timestamp": timestamp()})
            console.print(Text(f"\n{title}:", style="bold green"))
            console.print(Markdown(reply))

        elif user_input.lower() == "lookup":
            term = Prompt.ask("🔍 Enter keyword to search").strip().lower()
            results = [h for h in history if h.get("message") and term in h["message"].lower()]

            if not results:
                console.print(f"[yellow]No results found for '{term}'.[/yellow]")
            else:
                for msg in results[:10]:  # Show first 10 results
                    console.print(f"[{msg['timestamp']}] [{msg['role']}]: {msg['message'][:100]}...")

        elif user_input.lower() == "retry":
            user_msgs = [h for h in history if h["role"] == "user"]
            if not user_msgs:
                console.print("[red]No user messages to retry.[/red]")
                continue

            console.print("[cyan]Last 5 user messages:[/cyan]")
            msgs_to_show = user_msgs[-5:]
            for i, msg in enumerate(msgs_to_show, 1):
                console.print(f"{i}. {msg['message'][:100]}")

            retry_input = Prompt.ask("Select message to retry (number or Q)", default="1")
            if retry_input.lower() == "q":
                continue
            
            idx = int(retry_input) - 1
            if 0 <= idx < len(msgs_to_show):
                retry_msg = msgs_to_show[idx]["message"]
                history.append({"role": "user", "message": retry_msg, "timestamp": timestamp()})
                
                with console.status(f"[bold yellow]⚡ {title} is thinking...[/bold yellow]"):
                    try:
                        response = chat.send_message(retry_msg)
                        reply = "".join(part.text for part in response.candidates[0].content.parts if hasattr(part, "text"))
                    except Exception as e:
                        reply = f"[Error: {e}]"

                history.append({"role": "model", "message": reply, "timestamp": timestamp()})
                console.print(Text(f"\n{title}:", style="bold green"))
                console.print(Markdown(reply))

        elif user_input.lower() == "new":
            save_chat(session_name, history, password, chat_dir)
            console.print(f"[green]Starting new {title} chat...[/green]")
            return

        elif user_input.lower() == "load":
            save_chat(session_name, history, password, chat_dir)
            console.print(f"[yellow]Loading another {title} session...[/yellow]")
            new_session, new_password = session_menu(chat_dir, f"{title} Session Menu")
            if new_session:
                return start_chat(new_session, new_password, model_name, chat_dir, export_dir, persona, title)

        else:
            # Normal message
            current_timestamp = timestamp()
            history.append({"role": "user", "message": user_input, "timestamp": current_timestamp})

            with console.status(f"[bold yellow]⚡ {title} is thinking...[/bold yellow]"):
                try:
                    response = chat.send_message(user_input)
                    reply = "".join(part.text for part in response.candidates[0].content.parts if hasattr(part, "text"))
                except Exception as e:
                    reply = f"[Error: {e}]"

            history.append({"role": "model", "message": reply, "timestamp": timestamp()})
            console.print(Text(f"\n{title}:", style="bold green"))
            console.print(Markdown(reply))

        save_chat(session_name, history, password, chat_dir)

# ============= ENTRY POINTS =============

def gemini_ai_console():
    """Gemini AI console entry point."""
    clear_screen()
    gemini_display_title()
    session, password = session_menu(gemini_chat_dir, "Gemini Session Menu")
    if session:
        start_chat(session, password, GEMINI_MODEL, gemini_chat_dir, gemini_export_dir, title="Gemini")

def kali_sage_ai_console():
    """Kali Sage AI console entry point."""
    clear_screen()
    kali_sage_display_title()
    session, password = session_menu(kali_sage_chat_dir, "🛡️ Kali Sage Session Menu")
    if session:
        start_chat(session, password, KALI_SAGE_MODEL, kali_sage_chat_dir, kali_sage_export_dir, 
                   persona=KALI_SAGE_PERSONA, title="Kali Sage")

def ai_menu_title():
    """Display main menu banner."""
    banner = """
        .aMMMb  dMP        .aMMMb  dMP dMP .aMMMb dMMMMMMP 
       dMP"dMP amr        dMP"VMP dMP dMP dMP"dMP   dMP    
      dMMMMMP dMP        dMP     dMMMMMP dMMMMMP   dMP     
     dMP dMP dMP        dMP.aMP dMP dMP dMP dMP   dMP      
    dMP dMP dMP         VMMMP" dMP dMP dMP dMP   dMP       
                    AI TERMINAL CHAT
"""
    colors = ["#337AFF", "#33FFFF", "#00FF9D"]
    rgb_colors = [_hex_to_rgb(c) for c in colors]

    chars = list(banner)
    visible_positions = [i for i, ch in enumerate(chars) if ch != "\n"]
    total = len(visible_positions)

    text = Text()
    used = 0
    for ch in chars:
        if ch == "\n":
            text.append("\n")
            continue

        ratio = used / (total - 1) if total > 1 else 0.0

        if ratio <= 0.5:
            seg_ratio = ratio / 0.5
            c1, c2 = rgb_colors[0], rgb_colors[1]
        else:
            seg_ratio = (ratio - 0.5) / 0.5
            c1, c2 = rgb_colors[1], rgb_colors[2]

        r = int(c1[0] + (c2[0] - c1[0]) * seg_ratio)
        g = int(c1[1] + (c2[1] - c1[1]) * seg_ratio)
        b = int(c1[2] + (c2[2] - c1[2]) * seg_ratio)
        color = f"#{r:02x}{g:02x}{b:02x}"

        text.append(ch, style=f"bold {color}")
        used += 1

    console.print(text)

def ai_menu():
    """Main menu."""
    while True:
        clear_screen()
        ai_menu_title()
        print("=" * 40)
        print("AI CLI Chat Prompt")
        print("=" * 40)
        print("1. Google Gemini AI")
        print("2. Kali Sage AI")
        print("3. Exit")
        print("=" * 40)

        choice = input("Enter your choice (1-3): ").strip()
        if choice == "1":
            gemini_ai_console()
        elif choice == "2":
            kali_sage_ai_console()
        elif choice == "3":
            console.print("[green]Goodbye![/green]")
            break
        else:
            print("Invalid choice. Please enter 1-3.")
            time.sleep(1)

if __name__ == "__main__":
    ai_menu()