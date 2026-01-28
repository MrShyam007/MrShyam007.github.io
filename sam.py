#Network Monitoring & Port Scanner Tool
 #Author : Shyam Kumar Sharma


import socket
import os
import time
import csv
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext

ip_activity = {}
scan_data = {}
scan_history = []

LOG_FILE = "network_activity.log"
CSV_FILE = "scan_report.csv"

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def port_scan(ip, start_port, end_port):
    open_ports = []
    start_time = time.time()

    output.insert(tk.END, f"\n🔍 Scanning IP: {ip}\n")
    log_event(f"Started scan on {ip}")

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))

        if result == 0:
            open_ports.append(port)
            output.insert(tk.END, f"🟢 OPEN Port {port}\n")

        sock.close()
        root.update()

    duration = round(time.time() - start_time, 2)

    scan_data[ip] = {
        "open_ports": open_ports,
        "scan_time": duration
    }

    output.insert(tk.END, f"\n✅ Scan completed in {duration} seconds\n")
    return open_ports, duration


def monitor_ip(ip):
    ip_activity[ip] = ip_activity.get(ip, 0) + 1


def auto_suggestions(attack_type):
    suggestions = {
        "Port Scanning Attack": [
            "Close unused ports",
            "Apply firewall rules",
            "Allow only required services"
        ],
        "Brute Force / Suspicious Attempt": [
            "Enable strong password policy",
            "Limit login attempts",
            "Enable intrusion prevention"
        ],
        "Normal Activity": [
            "System behavior is normal",
            "Continue monitoring"
        ]
    }

    output.insert(tk.END, "\n🛡️ SECURITY RECOMMENDATIONS\n", "suggest")
    for s in suggestions.get(attack_type, []):
        output.insert(tk.END, f"✔ {s}\n", "suggest")


def analyze_threat(ip):
    open_ports = len(scan_data[ip]["open_ports"])
    scan_time = scan_data[ip]["scan_time"]
    access_count = ip_activity[ip]

    risk_score = 0
    attack_type = "Normal Activity"
    risk_level = "LOW"

    if access_count >= 5:
        risk_score += 30

    if open_ports >= 10 and scan_time <= 5:
        risk_score += 40
        attack_type = "Port Scanning Attack"

    if access_count >= 8:
        risk_score += 30
        attack_type = "Brute Force / Suspicious Attempt"

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"

    output.insert(tk.END, "\n🚨 THREAT ANALYSIS 🚨\n", "alert")
    output.insert(tk.END, f"Attack Type : {attack_type}\n", "alert")
    output.insert(tk.END, f"Risk Level  : {risk_level}\n", "alert")
    output.insert(tk.END, f"Risk Score  : {risk_score}/100\n", "alert")

    auto_suggestions(attack_type)

    # Save history
    scan_history.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "attack": attack_type,
        "risk": risk_level
    })

    export_csv(ip, attack_type, risk_level, risk_score)
    log_event(f"{ip} | {attack_type} | Risk {risk_level}")


def export_csv(ip, attack_type, risk_level, risk_score):
    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "Timestamp", "IP", "Open Ports",
                "Scan Time", "Access Count",
                "Attack Type", "Risk Level", "Risk Score"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            ",".join(map(str, scan_data[ip]["open_ports"])),
            scan_data[ip]["scan_time"],
            ip_activity[ip],
            attack_type,
            risk_level,
            risk_score
        ])


def view_history():
    output.insert(tk.END, "\n📜 SCAN HISTORY\n", "history")
    if not scan_history:
        output.insert(tk.END, "No scan history available\n")
        return

    for h in scan_history:
        output.insert(
            tk.END,
            f"{h['time']} | IP: {h['ip']} | {h['attack']} | Risk: {h['risk']}\n",
            "history"
        )


def start_scan():
    ip = ip_entry.get()

    if not is_valid_ip(ip):
        messagebox.showerror("Error", "Invalid IP Address")
        return

    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Ports must be numbers")
        return

    monitor_ip(ip)
    port_scan(ip, start_port, end_port)
    analyze_threat(ip)

def clear_output():
    output.delete(1.0, tk.END)


root = tk.Tk()
root.title("Network Monitoring & Port Scanner Tool")
root.geometry("900x700")
root.configure(bg="#020617")

tk.Label(
    root,
    text="🔐 Network Monitoring & Port Scanner Tool",
    font=("Segoe UI", 18, "bold"),
    fg="#38bdf8", bg="#020617"
).pack(pady=10)

frame = tk.Frame(root, bg="#020617")
frame.pack()

tk.Label(frame, text="Target IP", fg="white", bg="#020617").grid(row=0, column=0)
ip_entry = tk.Entry(frame, width=15)
ip_entry.grid(row=0, column=1, padx=5)

tk.Label(frame, text="Start Port", fg="white", bg="#020617").grid(row=0, column=2)
start_port_entry = tk.Entry(frame, width=10)
start_port_entry.grid(row=0, column=3)

tk.Label(frame, text="End Port", fg="white", bg="#020617").grid(row=0, column=4)
end_port_entry = tk.Entry(frame, width=10)
end_port_entry.grid(row=0, column=5)

btn = tk.Frame(root, bg="#020617")
btn.pack(pady=10)

tk.Button(btn, text="Start Scan", command=start_scan,
          bg="#22c55e", width=15).grid(row=0, column=0, padx=10)

tk.Button(btn, text="View History", command=view_history,
          bg="#0ea5e9", width=15).grid(row=0, column=1, padx=10)

tk.Button(btn, text="Clear Output", command=clear_output,
          bg="#ef4444", width=15).grid(row=0, column=2, padx=10)

output = scrolledtext.ScrolledText(
    root, width=110, height=26,
    bg="#020617", fg="#e5e7eb",
    font=("Consolas", 10)
)
output.pack()

output.tag_config("alert", foreground="#f87171")
output.tag_config("suggest", foreground="#a7f3d0")
output.tag_config("history", foreground="#fde68a")

root.mainloop()#Network Monitoring & Port Scanner Tool
 #Author : Shyam Kumar Sharma


import socket
import os
import time
import csv
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext

ip_activity = {}
scan_data = {}
scan_history = []

LOG_FILE = "network_activity.log"
CSV_FILE = "scan_report.csv"

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def port_scan(ip, start_port, end_port):
    open_ports = []
    start_time = time.time()

    output.insert(tk.END, f"\n🔍 Scanning IP: {ip}\n")
    log_event(f"Started scan on {ip}")

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))

        if result == 0:
            open_ports.append(port)
            output.insert(tk.END, f"🟢 OPEN Port {port}\n")

        sock.close()
        root.update()

    duration = round(time.time() - start_time, 2)

    scan_data[ip] = {
        "open_ports": open_ports,
        "scan_time": duration
    }

    output.insert(tk.END, f"\n✅ Scan completed in {duration} seconds\n")
    return open_ports, duration


def monitor_ip(ip):
    ip_activity[ip] = ip_activity.get(ip, 0) + 1


def auto_suggestions(attack_type):
    suggestions = {
        "Port Scanning Attack": [
            "Close unused ports",
            "Apply firewall rules",
            "Allow only required services"
        ],
        "Brute Force / Suspicious Attempt": [
            "Enable strong password policy",
            "Limit login attempts",
            "Enable intrusion prevention"
        ],
        "Normal Activity": [
            "System behavior is normal",
            "Continue monitoring"
        ]
    }

    output.insert(tk.END, "\n🛡️ SECURITY RECOMMENDATIONS\n", "suggest")
    for s in suggestions.get(attack_type, []):
        output.insert(tk.END, f"✔ {s}\n", "suggest")


def analyze_threat(ip):
    open_ports = len(scan_data[ip]["open_ports"])
    scan_time = scan_data[ip]["scan_time"]
    access_count = ip_activity[ip]

    risk_score = 0
    attack_type = "Normal Activity"
    risk_level = "LOW"

    if access_count >= 5:
        risk_score += 30

    if open_ports >= 10 and scan_time <= 5:
        risk_score += 40
        attack_type = "Port Scanning Attack"

    if access_count >= 8:
        risk_score += 30
        attack_type = "Brute Force / Suspicious Attempt"

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"

    output.insert(tk.END, "\n🚨 THREAT ANALYSIS 🚨\n", "alert")
    output.insert(tk.END, f"Attack Type : {attack_type}\n", "alert")
    output.insert(tk.END, f"Risk Level  : {risk_level}\n", "alert")
    output.insert(tk.END, f"Risk Score  : {risk_score}/100\n", "alert")

    auto_suggestions(attack_type)

    # Save history
    scan_history.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "attack": attack_type,
        "risk": risk_level
    })

    export_csv(ip, attack_type, risk_level, risk_score)
    log_event(f"{ip} | {attack_type} | Risk {risk_level}")


def export_csv(ip, attack_type, risk_level, risk_score):
    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "Timestamp", "IP", "Open Ports",
                "Scan Time", "Access Count",
                "Attack Type", "Risk Level", "Risk Score"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            ",".join(map(str, scan_data[ip]["open_ports"])),
            scan_data[ip]["scan_time"],
            ip_activity[ip],
            attack_type,
            risk_level,
            risk_score
        ])


def view_history():
    output.insert(tk.END, "\n📜 SCAN HISTORY\n", "history")
    if not scan_history:
        output.insert(tk.END, "No scan history available\n")
        return

    for h in scan_history:
        output.insert(
            tk.END,
            f"{h['time']} | IP: {h['ip']} | {h['attack']} | Risk: {h['risk']}\n",
            "history"
        )


def start_scan():
    ip = ip_entry.get()

    if not is_valid_ip(ip):
        messagebox.showerror("Error", "Invalid IP Address")
        return

    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Ports must be numbers")
        return

    monitor_ip(ip)
    port_scan(ip, start_port, end_port)
    analyze_threat(ip)

def clear_output():
    output.delete(1.0, tk.END)


root = tk.Tk()
root.title("Network Monitoring & Port Scanner Tool")
root.geometry("900x700")
root.configure(bg="#020617")

tk.Label(
    root,
    text="🔐 Network Monitoring & Port Scanner Tool",
    font=("Segoe UI", 18, "bold"),
    fg="#38bdf8", bg="#020617"
).pack(pady=10)

frame = tk.Frame(root, bg="#020617")
frame.pack()

tk.Label(frame, text="Target IP", fg="white", bg="#020617").grid(row=0, column=0)
ip_entry = tk.Entry(frame, width=15)
ip_entry.grid(row=0, column=1, padx=5)

tk.Label(frame, text="Start Port", fg="white", bg="#020617").grid(row=0, column=2)
start_port_entry = tk.Entry(frame, width=10)
start_port_entry.grid(row=0, column=3)

tk.Label(frame, text="End Port", fg="white", bg="#020617").grid(row=0, column=4)
end_port_entry = tk.Entry(frame, width=10)
end_port_entry.grid(row=0, column=5)

btn = tk.Frame(root, bg="#020617")
btn.pack(pady=10)

tk.Button(btn, text="Start Scan", command=start_scan,
          bg="#22c55e", width=15).grid(row=0, column=0, padx=10)

tk.Button(btn, text="View History", command=view_history,
          bg="#0ea5e9", width=15).grid(row=0, column=1, padx=10)

tk.Button(btn, text="Clear Output", command=clear_output,
          bg="#ef4444", width=15).grid(row=0, column=2, padx=10)

output = scrolledtext.ScrolledText(
    root, width=110, height=26,
    bg="#020617", fg="#e5e7eb",
    font=("Consolas", 10)
)
output.pack()

output.tag_config("alert", foreground="#f87171")
output.tag_config("suggest", foreground="#a7f3d0")
output.tag_config("history", foreground="#fde68a")

root.mainloop()#Network Monitoring & Port Scanner Tool
 #Author : Shyam Kumar Sharma


import socket
import os
import time
import csv
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext

ip_activity = {}
scan_data = {}
scan_history = []

LOG_FILE = "network_activity.log"
CSV_FILE = "scan_report.csv"

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def port_scan(ip, start_port, end_port):
    open_ports = []
    start_time = time.time()

    output.insert(tk.END, f"\n🔍 Scanning IP: {ip}\n")
    log_event(f"Started scan on {ip}")

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))

        if result == 0:
            open_ports.append(port)
            output.insert(tk.END, f"🟢 OPEN Port {port}\n")

        sock.close()
        root.update()

    duration = round(time.time() - start_time, 2)

    scan_data[ip] = {
        "open_ports": open_ports,
        "scan_time": duration
    }

    output.insert(tk.END, f"\n✅ Scan completed in {duration} seconds\n")
    return open_ports, duration


def monitor_ip(ip):
    ip_activity[ip] = ip_activity.get(ip, 0) + 1


def auto_suggestions(attack_type):
    suggestions = {
        "Port Scanning Attack": [
            "Close unused ports",
            "Apply firewall rules",
            "Allow only required services"
        ],
        "Brute Force / Suspicious Attempt": [
            "Enable strong password policy",
            "Limit login attempts",
            "Enable intrusion prevention"
        ],
        "Normal Activity": [
            "System behavior is normal",
            "Continue monitoring"
        ]
    }

    output.insert(tk.END, "\n🛡️ SECURITY RECOMMENDATIONS\n", "suggest")
    for s in suggestions.get(attack_type, []):
        output.insert(tk.END, f"✔ {s}\n", "suggest")


def analyze_threat(ip):
    open_ports = len(scan_data[ip]["open_ports"])
    scan_time = scan_data[ip]["scan_time"]
    access_count = ip_activity[ip]

    risk_score = 0
    attack_type = "Normal Activity"
    risk_level = "LOW"

    if access_count >= 5:
        risk_score += 30

    if open_ports >= 10 and scan_time <= 5:
        risk_score += 40
        attack_type = "Port Scanning Attack"

    if access_count >= 8:
        risk_score += 30
        attack_type = "Brute Force / Suspicious Attempt"

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"

    output.insert(tk.END, "\n🚨 THREAT ANALYSIS 🚨\n", "alert")
    output.insert(tk.END, f"Attack Type : {attack_type}\n", "alert")
    output.insert(tk.END, f"Risk Level  : {risk_level}\n", "alert")
    output.insert(tk.END, f"Risk Score  : {risk_score}/100\n", "alert")

    auto_suggestions(attack_type)

    # Save history
    scan_history.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "attack": attack_type,
        "risk": risk_level
    })

    export_csv(ip, attack_type, risk_level, risk_score)
    log_event(f"{ip} | {attack_type} | Risk {risk_level}")


def export_csv(ip, attack_type, risk_level, risk_score):
    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "Timestamp", "IP", "Open Ports",
                "Scan Time", "Access Count",
                "Attack Type", "Risk Level", "Risk Score"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            ",".join(map(str, scan_data[ip]["open_ports"])),
            scan_data[ip]["scan_time"],
            ip_activity[ip],
            attack_type,
            risk_level,
            risk_score
        ])


def view_history():
    output.insert(tk.END, "\n📜 SCAN HISTORY\n", "history")
    if not scan_history:
        output.insert(tk.END, "No scan history available\n")
        return

    for h in scan_history:
        output.insert(
            tk.END,
            f"{h['time']} | IP: {h['ip']} | {h['attack']} | Risk: {h['risk']}\n",
            "history"
        )


def start_scan():
    ip = ip_entry.get()

    if not is_valid_ip(ip):
        messagebox.showerror("Error", "Invalid IP Address")
        return

    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Ports must be numbers")
        return

    monitor_ip(ip)
    port_scan(ip, start_port, end_port)
    analyze_threat(ip)

def clear_output():
    output.delete(1.0, tk.END)


root = tk.Tk()
root.title("Network Monitoring & Port Scanner Tool")
root.geometry("900x700")
root.configure(bg="#020617")

tk.Label(
    root,
    text="🔐 Network Monitoring & Port Scanner Tool",
    font=("Segoe UI", 18, "bold"),
    fg="#38bdf8", bg="#020617"
).pack(pady=10)

frame = tk.Frame(root, bg="#020617")
frame.pack()

tk.Label(frame, text="Target IP", fg="white", bg="#020617").grid(row=0, column=0)
ip_entry = tk.Entry(frame, width=15)
ip_entry.grid(row=0, column=1, padx=5)

tk.Label(frame, text="Start Port", fg="white", bg="#020617").grid(row=0, column=2)
start_port_entry = tk.Entry(frame, width=10)
start_port_entry.grid(row=0, column=3)

tk.Label(frame, text="End Port", fg="white", bg="#020617").grid(row=0, column=4)
end_port_entry = tk.Entry(frame, width=10)
end_port_entry.grid(row=0, column=5)

btn = tk.Frame(root, bg="#020617")
btn.pack(pady=10)

tk.Button(btn, text="Start Scan", command=start_scan,
          bg="#22c55e", width=15).grid(row=0, column=0, padx=10)

tk.Button(btn, text="View History", command=view_history,
          bg="#0ea5e9", width=15).grid(row=0, column=1, padx=10)

tk.Button(btn, text="Clear Output", command=clear_output,
          bg="#ef4444", width=15).grid(row=0, column=2, padx=10)

output = scrolledtext.ScrolledText(
    root, width=110, height=26,
    bg="#020617", fg="#e5e7eb",
    font=("Consolas", 10)
)
output.pack()

output.tag_config("alert", foreground="#f87171")
output.tag_config("suggest", foreground="#a7f3d0")
output.tag_config("history", foreground="#fde68a")

root.mainloop()#Network Monitoring & Port Scanner Tool
 #Author : Shyam Kumar Sharma


import socket
import os
import time
import csv
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext

ip_activity = {}
scan_data = {}
scan_history = []

LOG_FILE = "network_activity.log"
CSV_FILE = "scan_report.csv"

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def port_scan(ip, start_port, end_port):
    open_ports = []
    start_time = time.time()

    output.insert(tk.END, f"\n🔍 Scanning IP: {ip}\n")
    log_event(f"Started scan on {ip}")

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))

        if result == 0:
            open_ports.append(port)
            output.insert(tk.END, f"🟢 OPEN Port {port}\n")

        sock.close()
        root.update()

    duration = round(time.time() - start_time, 2)

    scan_data[ip] = {
        "open_ports": open_ports,
        "scan_time": duration
    }

    output.insert(tk.END, f"\n✅ Scan completed in {duration} seconds\n")
    return open_ports, duration


def monitor_ip(ip):
    ip_activity[ip] = ip_activity.get(ip, 0) + 1


def auto_suggestions(attack_type):
    suggestions = {
        "Port Scanning Attack": [
            "Close unused ports",
            "Apply firewall rules",
            "Allow only required services"
        ],
        "Brute Force / Suspicious Attempt": [
            "Enable strong password policy",
            "Limit login attempts",
            "Enable intrusion prevention"
        ],
        "Normal Activity": [
            "System behavior is normal",
            "Continue monitoring"
        ]
    }

    output.insert(tk.END, "\n🛡️ SECURITY RECOMMENDATIONS\n", "suggest")
    for s in suggestions.get(attack_type, []):
        output.insert(tk.END, f"✔ {s}\n", "suggest")


def analyze_threat(ip):
    open_ports = len(scan_data[ip]["open_ports"])
    scan_time = scan_data[ip]["scan_time"]
    access_count = ip_activity[ip]

    risk_score = 0
    attack_type = "Normal Activity"
    risk_level = "LOW"

    if access_count >= 5:
        risk_score += 30

    if open_ports >= 10 and scan_time <= 5:
        risk_score += 40
        attack_type = "Port Scanning Attack"

    if access_count >= 8:
        risk_score += 30
        attack_type = "Brute Force / Suspicious Attempt"

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"

    output.insert(tk.END, "\n🚨 THREAT ANALYSIS 🚨\n", "alert")
    output.insert(tk.END, f"Attack Type : {attack_type}\n", "alert")
    output.insert(tk.END, f"Risk Level  : {risk_level}\n", "alert")
    output.insert(tk.END, f"Risk Score  : {risk_score}/100\n", "alert")

    auto_suggestions(attack_type)

    # Save history
    scan_history.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "attack": attack_type,
        "risk": risk_level
    })

    export_csv(ip, attack_type, risk_level, risk_score)
    log_event(f"{ip} | {attack_type} | Risk {risk_level}")


def export_csv(ip, attack_type, risk_level, risk_score):
    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "Timestamp", "IP", "Open Ports",
                "Scan Time", "Access Count",
                "Attack Type", "Risk Level", "Risk Score"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            ",".join(map(str, scan_data[ip]["open_ports"])),
            scan_data[ip]["scan_time"],
            ip_activity[ip],
            attack_type,
            risk_level,
            risk_score
        ])


def view_history():
    output.insert(tk.END, "\n📜 SCAN HISTORY\n", "history")
    if not scan_history:
        output.insert(tk.END, "No scan history available\n")
        return

    for h in scan_history:
        output.insert(
            tk.END,
            f"{h['time']} | IP: {h['ip']} | {h['attack']} | Risk: {h['risk']}\n",
            "history"
        )


def start_scan():
    ip = ip_entry.get()

    if not is_valid_ip(ip):
        messagebox.showerror("Error", "Invalid IP Address")
        return

    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Ports must be numbers")
        return

    monitor_ip(ip)
    port_scan(ip, start_port, end_port)
    analyze_threat(ip)

def clear_output():
    output.delete(1.0, tk.END)


root = tk.Tk()
root.title("Network Monitoring & Port Scanner Tool")
root.geometry("900x700")
root.configure(bg="#020617")

tk.Label(
    root,
    text="🔐 Network Monitoring & Port Scanner Tool",
    font=("Segoe UI", 18, "bold"),
    fg="#38bdf8", bg="#020617"
).pack(pady=10)

frame = tk.Frame(root, bg="#020617")
frame.pack()

tk.Label(frame, text="Target IP", fg="white", bg="#020617").grid(row=0, column=0)
ip_entry = tk.Entry(frame, width=15)
ip_entry.grid(row=0, column=1, padx=5)

tk.Label(frame, text="Start Port", fg="white", bg="#020617").grid(row=0, column=2)
start_port_entry = tk.Entry(frame, width=10)
start_port_entry.grid(row=0, column=3)

tk.Label(frame, text="End Port", fg="white", bg="#020617").grid(row=0, column=4)
end_port_entry = tk.Entry(frame, width=10)
end_port_entry.grid(row=0, column=5)

btn = tk.Frame(root, bg="#020617")
btn.pack(pady=10)

tk.Button(btn, text="Start Scan", command=start_scan,
          bg="#22c55e", width=15).grid(row=0, column=0, padx=10)

tk.Button(btn, text="View History", command=view_history,
          bg="#0ea5e9", width=15).grid(row=0, column=1, padx=10)

tk.Button(btn, text="Clear Output", command=clear_output,
          bg="#ef4444", width=15).grid(row=0, column=2, padx=10)

output = scrolledtext.ScrolledText(
    root, width=110, height=26,
    bg="#020617", fg="#e5e7eb",
    font=("Consolas", 10)
)
output.pack()

output.tag_config("alert", foreground="#f87171")
output.tag_config("suggest", foreground="#a7f3d0")
output.tag_config("history", foreground="#fde68a")

root.mainloop()
