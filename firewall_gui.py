import psutil
import pydivert
import socket
import threading
import tkinter as tk
from tkinter import messagebox, ttk
import json
import os


# 🔥 Firewall Rules (Auto Load)
BLOCKED_IPS = set()
BLOCKED_PORTS = set()
BLOCKED_DOMAINS = set()
BLOCKED_PROCESSES = set()
LOGS = []

# 🔄 Persistent Storage File
CONFIG_FILE = "firewall_rules.json"

def load_rules():
    """Loads firewall rules from a JSON file on startup."""
    global BLOCKED_IPS, BLOCKED_PORTS, BLOCKED_DOMAINS, BLOCKED_PROCESSES

    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
            BLOCKED_IPS = set(data.get("ips", []))
            BLOCKED_PORTS = set(data.get("ports", []))
            BLOCKED_DOMAINS = set(data.get("domains", []))
            BLOCKED_PROCESSES = set(data.get("processes", []))

            
#load rules before startint the GUI
load_rules()


def save_rules():
    """Saves firewall rules to a JSON file to persist after restart."""
    data = {
        "ips": list(BLOCKED_IPS),
        "ports": list(BLOCKED_PORTS),
        "domains": list(BLOCKED_DOMAINS),
        "processes": list(BLOCKED_PROCESSES)
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=4)


# 🚀 DNS Resolution for Domain Blocking
def resolve_domains():
    resolved_ips = set()
    for domain in BLOCKED_DOMAINS:
        try:
            ip = socket.gethostbyname(domain)
            resolved_ips.add(ip)
        except Exception:
            pass
    return resolved_ips

# 🔥 Firewall Logic
def firewall():
    resolved_blocked_ips = resolve_domains()
    with pydivert.WinDivert("tcp or udp") as w:
        for packet in w:
            if packet.src_addr in BLOCKED_IPS or packet.dst_addr in BLOCKED_IPS or packet.dst_addr in resolved_blocked_ips:
                log_block(packet, "Blocked IP/Domain")
                continue
            
            if packet.dst_port in BLOCKED_PORTS or packet.src_port in BLOCKED_PORTS:
                log_block(packet, "Blocked Port")
                continue

            if get_process_name(packet.src_port) in BLOCKED_PROCESSES or get_process_name(packet.dst_port) in BLOCKED_PROCESSES:
                log_block(packet, "Blocked Process")
                continue
            
            w.send(packet)  # Allow packet

# 🛑 Log Blocked Packets
def log_block(packet, reason):
    log_entry = f"[{reason}] {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}"
    LOGS.append(log_entry)
    logs_list.insert(tk.END, log_entry)
    print(log_entry)

# 🧐 Get Process Name by Port
def get_process_name(port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port:
            try:
                return psutil.Process(conn.pid).name() if conn.pid else None
            except psutil.NoSuchProcess:
                return None
    return None

# 🎨 GUI Setup
app = tk.Tk()
app.title("🔥 Windows Firewall GUI")
app.geometry("600x400")

# 🔹 Tabbed Interface
notebook = ttk.Notebook(app)
home_tab = ttk.Frame(notebook)
domains_tab = ttk.Frame(notebook)
apps_tab = ttk.Frame(notebook)
ports_tab = ttk.Frame(notebook)
logs_tab = ttk.Frame(notebook)

notebook.add(home_tab, text="Home")
notebook.add(domains_tab, text="Blocked Domains")
notebook.add(apps_tab, text="Blocked Apps")
notebook.add(ports_tab, text="Blocked Ports")
notebook.add(logs_tab, text="Logs")
notebook.pack(expand=1, fill="both")

# ✅ Home Tab
ttk.Label(home_tab, text="Windows Firewall Control", font=("Arial", 14)).pack(pady=10)
tk.Button(home_tab, text="Start Firewall", command=lambda: threading.Thread(target=firewall, daemon=True).start()).pack(pady=5)
tk.Button(home_tab, text="Stop Firewall", command=lambda: messagebox.showinfo("Firewall", "Restart script to fully stop!")).pack(pady=5)

# 🛑 Blocked Domains Tab
ttk.Label(domains_tab, text="Blocked Domains").pack()
domains_list = tk.Listbox(domains_tab)
domains_list.pack(pady=10, fill="both", expand=True)

domain_entry = tk.Entry(domains_tab, width=30)
domain_entry.pack(pady=5)
tk.Button(domains_tab, text="Add Domain", command=lambda: add_domain(domain_entry.get())).pack(pady=5)
tk.Button(domains_tab, text="Remove Domain", command=lambda: remove_selected(domains_list, BLOCKED_DOMAINS)).pack(pady=5)

# 🚫 Blocked Apps Tab
ttk.Label(apps_tab, text="Blocked Applications").pack()
apps_list = tk.Listbox(apps_tab)
apps_list.pack(pady=10, fill="both", expand=True)

app_entry = tk.Entry(apps_tab, width=30)
app_entry.pack(pady=5)
tk.Button(apps_tab, text="Add App", command=lambda: add_process(app_entry.get())).pack(pady=5)
tk.Button(apps_tab, text="Remove App", command=lambda: remove_selected(apps_list, BLOCKED_PROCESSES)).pack(pady=5)

# 🔥 Blocked Ports Tab
ttk.Label(ports_tab, text="Blocked Ports").pack()
ports_list = tk.Listbox(ports_tab)
ports_list.pack(pady=10, fill="both", expand=True)

port_entry = tk.Entry(ports_tab, width=30)
port_entry.pack(pady=5)
tk.Button(ports_tab, text="Add Port", command=lambda: add_port(port_entry.get())).pack(pady=5)
tk.Button(ports_tab, text="Remove Port", command=lambda: remove_selected(ports_list, BLOCKED_PORTS)).pack(pady=5)

# 📜 Logs Tab
ttk.Label(logs_tab, text="Blocked Requests").pack()
logs_list = tk.Listbox(logs_tab)
logs_list.pack(pady=10, fill="both", expand=True)
tk.Button(logs_tab, text="Clear Logs", command=lambda: logs_list.delete(0, tk.END)).pack(pady=5)
def add_domain(domain):
    """Adds a domain to the blocked list and saves rules."""
    if domain:
        BLOCKED_DOMAINS.add(domain)
        domains_list.insert(tk.END, domain)
        save_rules()
        messagebox.showinfo("Success", f"Blocked domain: {domain}")
def add_process(process):
    """Adds a process to the blocked list and saves rules."""
    if process:
        BLOCKED_PROCESSES.add(process)
        apps_list.insert(tk.END, process)
        save_rules()
        messagebox.showinfo("Success", f"Blocked process: {process}")


def add_port(port):
    """Adds a port to the blocked list and saves rules."""
    try:
        port = int(port)
        BLOCKED_PORTS.add(port)
        ports_list.insert(tk.END, str(port))
        save_rules()
        messagebox.showinfo("Success", f"Blocked Port: {port}")
    except ValueError:
        messagebox.showerror("Error", "Invalid Port Number")


def remove_selected(listbox, block_list):
    """Removes a selected rule and updates storage."""
    try:
        selected = listbox.get(tk.ACTIVE)
        block_list.discard(selected)
        listbox.delete(tk.ACTIVE)
        save_rules()
        messagebox.showinfo("Success", f"Removed: {selected}")
    except:
        messagebox.showerror("Error", "No item selected")


# 🎬 Run GUI
app.mainloop()
