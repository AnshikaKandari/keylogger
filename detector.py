import psutil
import os
import db

def detect_keylogger():
    suspicious_processes = []
    suspicious_files = []
    keylogger_keywords = ["keylog", "spy", "logger", "stealer", "record", "monitor", "capture"]

    print("🔍 Scanning running processes...")
    
    # Scan processes
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            process_name = proc.info['name'].lower() if proc.info['name'] else ""
            process_path = proc.info['exe'] if proc.info['exe'] else ""

            # 1. Suspicious keywords in process name (but ignore legitimate apps first)
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
            is_legitimate = any(app in process_name for app in legitimate_apps)
            
            if not is_legitimate:
                # Only check for suspicious keywords if it's not a legitimate app
                for word in keylogger_keywords:
                    if word in process_name:
                        suspicious_processes.append((proc.info['pid'], process_name, process_path))
                        break

            # 2. Process running from unusual location (not Windows/System folder)
            if process_path and not process_path.lower().startswith("c:\\windows"):
                if not is_legitimate:
                    suspicious_processes.append((proc.info['pid'], process_name, process_path))

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    print("🔍 Scanning for suspicious files...")
    
    # Scan files in current directory and common locations
    scan_dirs = [
        os.getcwd(),  # Current directory
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Documents")
    ]
    
    suspicious_extensions = ['.exe', '.py', '.bat', '.cmd', '.ps1', '.vbs', '.js']
    
    for scan_dir in scan_dirs:
        if os.path.exists(scan_dir):
            try:
                for root, dirs, files in os.walk(scan_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_name = file.lower()
                        file_ext = os.path.splitext(file)[1].lower()
                        
                        # Check if file has suspicious extension
                        if file_ext in suspicious_extensions:
                            # Check for suspicious keywords in filename
                            filename_suspicious = False
                            for keyword in keylogger_keywords:
                                if keyword in file_name:
                                    suspicious_files.append((file_path, "Suspicious filename"))
                                    filename_suspicious = True
                                    break
                            
                            # For Python files, also check content (only if filename wasn't already suspicious)
                            if file_ext == '.py' and not filename_suspicious:
                                # Skip detector files
                                if "detector" in file_name or "gui" in file_name:
                                    continue
                                    
                                try:
                                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read().lower()
                                        for keyword in keylogger_keywords:
                                            if keyword in content:
                                                suspicious_files.append((file_path, f"Suspicious content: {keyword}"))
                                                break
                                except:
                                    pass
                                    
            except PermissionError:
                continue

    # Display results
    print("\n" + "=" * 50)
    
    if suspicious_processes:
        print("⚠️ Suspicious processes detected (possible keyloggers):")
        for pid, name, path in suspicious_processes:
            print(f"   PID: {pid}, Process: {name}, Path: {path}")
    else:
        print("✅ No suspicious keylogger-like process detected.")
    
    if suspicious_files:
        print("\n⚠️ Suspicious files detected:")
        for file_path, reason in suspicious_files:
            print(f"   File: {file_path}")
            print(f"   Reason: {reason}")
    else:
        print("\n✅ No suspicious files detected.")
    
    print("\n" + "=" * 50)
    print(f"Total suspicious processes: {len(suspicious_processes)}")
    print(f"Total suspicious files: {len(suspicious_files)}")

    # Save results to database
    print("\n💾 Saving detection results to database...")
    for pid, name, path in suspicious_processes:
        db.save_detection('process', pid, name, path, 'Suspicious keywords or unusual location')

    for file_path, reason in suspicious_files:
        db.save_detection('file', None, None, file_path, reason)

    print("✅ Results saved successfully!")

# Run detector
if __name__ == "__main__":
    detect_keylogger()
