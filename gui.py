import tkinter as tk
from tkinter import ttk, messagebox
import psutil
from datetime import datetime

# Suspicious keywords list
SUSPICIOUS_KEYWORDS = [
    "keylog", "spy", "logger", "record", "stealer", 
    "monitor", "capture", "sniffer", "inject", "hack",
    "malware", "virus", "trojan", "worm", "exploit",
    "backdoor", "botnet", "miner", "ransom", "theft",
    "creds", "stealth", "rootkit", "rat", "hook"
]

# Function to scan processes
def scan_processes():
    # Clear old table entries
    for row in tree.get_children():
        tree.delete(row)

    suspicious_found = []
    total_processes = 0
    
    # Legitimate apps whitelist
    legitimate_apps = [
        # Browsers
        "chrome", "firefox", "edge", "opera", "brave", "safari",
        # Development tools
        "python", "code", "vscode", "cursor", "notepad", "sublime", "atom", "intellij", "eclipse", "android", "java", "node", "npm", "git", "docker", "postman",
        # Office apps
        "word", "excel", "powerpoint", "outlook", "office", "onenote", "access", "publisher",
        # Communication
        "teams", "discord", "slack", "zoom", "skype", "whatsapp", "telegram", "signal",
        # Media
        "spotify", "youtube", "netflix", "vlc", "media", "player",
        # Gaming
        "steam", "origin", "epic", "battle", "league", "valorant", "minecraft",
        # System services
        "windows", "defender", "security", "update", "service", "host", "helper", "broker", "sync", "cloud", "creative", "adobe", "oracle", "mysql", "sql", "wsl", "terminal", "console", "widget", "phone", "canva", "asus", "glidex", "shareit", "mcafee", "webadvisor", "registry", "memcompression", "tnslsnr", "nissrv", "ccxprocess", "coresync", "sdxhelper", "oledshifter", "desktop", "crash", "processor", "uihost", "openconsole", "msmpeng", "mpdefender", "antimalware"
    ]

    # Update status
    status_label.config(text="🔍 Scanning processes...", fg="#0078D7")
    root.update()

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            total_processes += 1
            pid = proc.info['pid']
            name = proc.info['name'] or "Unknown"
            path = proc.info['exe'] or "N/A"

            # Handle cmdline
            cmdline_list = proc.info.get('cmdline')
            if isinstance(cmdline_list, list):
                cmdline = " ".join(cmdline_list)
            else:
                cmdline = ""

            status = "Normal"
            
            # Check if it's a legitimate app first
            is_legitimate = any(app in name.lower() for app in legitimate_apps)
            
            if not is_legitimate:
                # Only check for suspicious keywords if it's not a legitimate app
                for keyword in SUSPICIOUS_KEYWORDS:
                    if (keyword.lower() in name.lower() or
                        keyword.lower() in path.lower() or
                        keyword.lower() in cmdline.lower()):
                        status = "🚨 Suspicious"
                        suspicious_found.append(f"{name} (PID: {pid}) → {cmdline}")
                        break

            if status == "🚨 Suspicious":
                tree.insert("", "end", values=(pid, name, path, status), tags=("suspicious",))
            else:
                tree.insert("", "end", values=(pid, name, path, status))

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # Update status and stats
    if suspicious_found:
        status_label.config(text=f"⚠️ {len(suspicious_found)} suspicious processes detected!", fg="#FF4444")
        messagebox.showwarning("🚨 Security Alert!", 
                              f"Found {len(suspicious_found)} suspicious processes!\n\n" + "\n".join(suspicious_found))
    else:
        status_label.config(text="✅ System is secure - No suspicious processes found", fg="#00AA44")
        messagebox.showinfo("🛡️ Security Check Complete", 
                           f"Scan completed successfully!\n\nTotal processes scanned: {total_processes}\nSuspicious processes: 0\n\nYour system appears to be secure.")

    # Update stats
    stats_label.config(text=f"📊 Scanned: {total_processes} processes | Suspicious: {len(suspicious_found)} | Time: {datetime.now().strftime('%H:%M:%S')}")

# ------------------- Modern GUI Design -------------------
root = tk.Tk()
root.title("🛡️ Advanced Security Scanner")
root.geometry("1000x700")
root.configure(bg="#1E1E1E")  # Dark theme

# Custom style for modern look
style = ttk.Style()
style.theme_use('clam')
style.configure("Treeview", 
                background="#2D2D2D", 
                foreground="white", 
                fieldbackground="#2D2D2D",
                rowheight=25)
style.configure("Treeview.Heading", 
                background="#0078D7", 
                foreground="white", 
                font=('Arial', 10, 'bold'))
style.map('Treeview', background=[('selected', '#0078D7')])

# Main container
main_frame = tk.Frame(root, bg="#1E1E1E")
main_frame.pack(fill="both", expand=True, padx=20, pady=20)

# Header section
header_frame = tk.Frame(main_frame, bg="#1E1E1E")
header_frame.pack(fill="x", pady=(0, 20))

# Title with icon
title_frame = tk.Frame(header_frame, bg="#1E1E1E")
title_frame.pack()

title_icon = tk.Label(title_frame, text="🛡️", font=("Arial", 24), bg="#1E1E1E", fg="#0078D7")
title_icon.pack(side="left", padx=(0, 10))

title_text = tk.Label(title_frame, text="Advanced Security Scanner", 
                     font=("Arial", 24, "bold"), bg="#1E1E1E", fg="white")
title_text.pack(side="left")

subtitle = tk.Label(header_frame, text="Real-time Keylogger & Spyware Detection System", 
                   font=("Arial", 12), bg="#1E1E1E", fg="#CCCCCC")
subtitle.pack(pady=(5, 0))

# Status section
status_frame = tk.Frame(main_frame, bg="#2D2D2D", relief="flat", bd=1)
status_frame.pack(fill="x", pady=(0, 20))

status_label = tk.Label(status_frame, text="🔄 Ready to scan", 
                       font=("Arial", 12, "bold"), bg="#2D2D2D", fg="#00AA44", pady=10)
status_label.pack()

# Stats section
stats_frame = tk.Frame(main_frame, bg="#2D2D2D", relief="flat", bd=1)
stats_frame.pack(fill="x", pady=(0, 20))

stats_label = tk.Label(stats_frame, text="📊 No scan performed yet", 
                      font=("Arial", 10), bg="#2D2D2D", fg="#CCCCCC", pady=8)
stats_label.pack()

# Table section
table_frame = tk.Frame(main_frame, bg="#2D2D2D", relief="flat", bd=1)
table_frame.pack(fill="both", expand=True, pady=(0, 20))

# Table title
table_title = tk.Label(table_frame, text="📋 Process Analysis Results", 
                      font=("Arial", 14, "bold"), bg="#2D2D2D", fg="white", pady=10)
table_title.pack()

# Treeview with scrollbars
tree_frame = tk.Frame(table_frame, bg="#2D2D2D")
tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

# Create Treeview
columns = ("PID", "Process", "Path", "Status")
tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12)

# Configure columns
tree.heading("PID", text="PID")
tree.heading("Process", text="Process Name")
tree.heading("Path", text="File Path")
tree.heading("Status", text="Security Status")

tree.column("PID", width=80, anchor="center")
tree.column("Process", width=200, anchor="w")
tree.column("Path", width=400, anchor="w")
tree.column("Status", width=150, anchor="center")

# Configure tags for styling
tree.tag_configure("suspicious", background="#FF4444", foreground="white")
tree.tag_configure("normal", background="#2D2D2D", foreground="white")

# Scrollbars
v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

# Pack tree and scrollbars
tree.grid(row=0, column=0, sticky="nsew")
v_scrollbar.grid(row=0, column=1, sticky="ns")
h_scrollbar.grid(row=1, column=0, sticky="ew")

tree_frame.grid_rowconfigure(0, weight=1)
tree_frame.grid_columnconfigure(0, weight=1)

# Button section
button_frame = tk.Frame(main_frame, bg="#1E1E1E")
button_frame.pack(pady=20)

# Modern scan button
scan_btn = tk.Button(button_frame, text="🔍 Start Security Scan", 
                    command=scan_processes, 
                    font=("Arial", 14, "bold"),
                    bg="#0078D7", fg="white", 
                    padx=30, pady=15,
                    relief="flat", bd=0,
                    cursor="hand2",
                    activebackground="#005A9E",
                    activeforeground="white")
scan_btn.pack(side="left", padx=(0, 10))

# Clear button
clear_btn = tk.Button(button_frame, text="🗑️ Clear Results", 
                     command=lambda: [tree.delete(item) for item in tree.get_children()] or status_label.config(text="🔄 Ready to scan", fg="#00AA44") or stats_label.config(text="📊 No scan performed yet"),
                     font=("Arial", 12),
                     bg="#666666", fg="white", 
                     padx=20, pady=10,
                     relief="flat", bd=0,
                     cursor="hand2",
                     activebackground="#555555",
                     activeforeground="white")
clear_btn.pack(side="left")

# Footer
footer_frame = tk.Frame(main_frame, bg="#1E1E1E")
footer_frame.pack(fill="x", pady=(20, 0))

footer_text = tk.Label(footer_frame, text="🛡️ Advanced Security Scanner v2.0 | Real-time Protection System", 
                      font=("Arial", 10), bg="#1E1E1E", fg="#888888")
footer_text.pack()

# Hover effects for buttons
def on_enter(e):
    e.widget['bg'] = '#005A9E' if e.widget == scan_btn else '#555555'

def on_leave(e):
    e.widget['bg'] = '#0078D7' if e.widget == scan_btn else '#666666'

scan_btn.bind("<Enter>", on_enter)
scan_btn.bind("<Leave>", on_leave)
clear_btn.bind("<Enter>", on_enter)
clear_btn.bind("<Leave>", on_leave)

root.mainloop()
