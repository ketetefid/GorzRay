# GorzRay, an Xray GTK GUI for Linux, focusing on simplicity and enhancing VPN experience.
# Copyright (C) 2025 Kete Tefid

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
    
import json
import socket
import requests
import subprocess
import threading
import queue
import sys
import os
import time
import gi
import signal
import psutil
import tempfile
import shutil
import random
import ipaddress
from typing import List, Set, Tuple, Dict
from pathlib import Path
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib
import pystray
from PIL import Image, ImageDraw
import argparse

# The app's mode
current_mode = "proxy"
# The last connected entry
selected_file_path = None
# For storing processes
backend_procs = []

# To be bypassed in VPN mode
ip_list = []

# Placeholder pids
xray_pid = -999999
tun2proxy_pid = -999998

# This must be the same as TMPDIR env var set in AppRun[.wrapped]
TMPDIR = os.environ.get("TMPDIR", "/tmp/gorzray")

early_log_file = os.path.join(TMPDIR,"gorzray_app.log") 
xray_log_file = os.path.join(TMPDIR,"gorzray_xray.log")
tun_log_file = os.path.join(TMPDIR,"gorzray_tun2proxy.log")
output_config_path = os.path.join(TMPDIR,"gorzray_config.json")

# Create/Overwrite the log files
log_file = open(xray_log_file, "w")
log_file = open(tun_log_file, "w")

# The path to store the recent_files.json and sublink.txt
CONFIG_DIR = os.path.expanduser("~/.config/gorzray")
# The last used entry
LAST_FILE_PATH = os.path.join(CONFIG_DIR, "last_entry.txt")
# The json list of sublinks or configs
RECENT_FILES_PATH = os.path.join(CONFIG_DIR, "recent_files.json")

SOCKET_PATH = os.path.join(TMPDIR, "gorzray.sock")
# Max number of configs we shall store
MAX_RECENT_FILES = 20

# Corresponds to the AppDir env set by the AppImage
appdir = os.environ.get("APPDIR", os.path.dirname(__file__))

# Xray geo files directory
os.environ['XRAY_LOCATION_ASSET'] = f"{appdir}/usr/share/xray-geofiles"

# Icons for the tray
icon_image = Image.open(os.path.join(appdir, "gorzray-icon.png"))
icon_image_proxy = Image.open(os.path.join(appdir, "gorzray-icon-proxy.png"))
icon_image_vpn = Image.open(os.path.join(appdir, "gorzray-icon-vpn.png"))

# Create a temp dir for holding tun2proxy-bin and run_vpn.sh.
# We make temp_root a fixed path (here the same as our TMPDIR),
# so the polkit rule can work on run_vpn.sh.
temp_root = TMPDIR
# tun2proxy-bin will be saved here
os.makedirs(os.path.join(temp_root, "usr", "bin"), exist_ok=True)

# Print will write both to stdout and the
# early log file (reflected in xray log window)
class TeeOutput:
    def __init__(self, logfile_path):
        self.terminal = sys.__stdout__  # keep the real stdout
        self.log = open(logfile_path, "w", buffering=1)  # line-buffered

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

sys.stdout = TeeOutput(early_log_file)
sys.stderr = sys.stdout

# Proxy socks5 port
socks_port = None

# CF subnets
CLOUDFLARE_SUBNETS = [
    ipaddress.ip_network(net) for net in [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
    ]
]

# Set of fallback CF IPs
FALLBACK_IPS = {
    "104.21.97.182",
    "104.17.241.156",
    "104.17.80.212",
    "162.159.38.246",
    "162.159.4.186",
}

##############################################################################

def load_recent_files():
    if os.path.exists(RECENT_FILES_PATH):
        try:
            with open(RECENT_FILES_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []

##############################################################################

def save_selected_file(path):
    """ Adds the path to the json list of sublinks/configs. """
    os.makedirs(CONFIG_DIR, exist_ok=True)
    recent = load_recent_files()
    if path in recent:
        recent.remove(path)
    recent.insert(0, path)
    recent = recent[:MAX_RECENT_FILES]
    with open(RECENT_FILES_PATH, "w") as f:
        json.dump(recent, f)

##############################################################################

def omit_selected_file(path):
    """ Deletes a path from the list of sublinks/configs. """
    recent = load_recent_files()
    if path in recent:
        recent.remove(path)
    recent = recent[:MAX_RECENT_FILES]
    with open(RECENT_FILES_PATH, "w") as f:
        json.dump(recent, f)
        
##############################################################################
        
def save_last_selected_file(path):
    """ Stores the last entry used. """
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(LAST_FILE_PATH, "w") as f:
        f.write(path)

##############################################################################

def load_last_selected_file():
    """ Loads the last entry used. """
    if os.path.exists(LAST_FILE_PATH):
        with open(LAST_FILE_PATH, "r") as f:
            return f.read().strip()
    return None

##############################################################################
    
def download_json_from_url(url: str) -> dict:
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Failed to download the config file: {e}")
        return None

##############################################################################    

def resolve_to_ip(address: str) -> str:
    try:
        result = socket.getaddrinfo(address, None)
        return result[0][4][0]  # takes the first resolved IP (IPv4 or IPv6)
    except socket.gaierror:
        # If the resolution fails, VPN mode won't work
        return None

##############################################################################

def remove_direct_routes(xray_config):
    """
    To have a leak-free DNS experience and avoid routing loops, we can
    remove all routing rules with outboundTag == "direct" from an xray config.
    This would preserve the leak-free experience at the expense of breaking
    connection separation.
    """
    if "routing" in xray_config and "rules" in xray_config["routing"]:
        original_count = len(xray_config["routing"]["rules"])
        xray_config["routing"]["rules"] = [
            rule for rule in xray_config["routing"]["rules"]
            if rule.get("outboundTag") != "direct"
        ]
        removed_count = original_count - len(xray_config["routing"]["rules"])
        print(f"Removed {removed_count} direct route(s).")
    return xray_config
    
##############################################################################
    
def resolve_domains(config: dict) -> Tuple[List[str], dict]:
    """ 
    - Resolves the domains in outbounds for bypassing in VPN mode.
    - Supports vless/vmess, trojan & wireguard protocols.
    - Tries to replace the domains with their IPs, and adds them
      to the bypassed list, too.
    - Gets the socks port if exists.
    - Removes the direct routing rules if requested.
    """
    def is_ip(s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    global socks_port
    ips = set()
    patched_config = json.loads(json.dumps(config))

    inbounds = config.get("inbounds", [])
    socks_port = None
    for inbound in inbounds:
        if inbound.get("protocol") == "socks" or  inbound.get("protocol") == "mixed":
            socks_port = inbound.get("port")

    if not socks_port:
        print("The config doesn't have any socks inbound.")
        return None, None
        
    outbounds = patched_config.get("outbounds", [])
    if not isinstance(outbounds, list):
        print("The config doesn't have any outbounds.")
        return None, None


    for outbound in outbounds:
        settings = outbound.get("settings")
        if not isinstance(settings, dict):
            continue

        # vmess/vless : the older subscription json formats
        vnext = settings.get("vnext")
        if isinstance(vnext, list):
            for server in vnext:
                if not isinstance(server, dict):
                    continue

                address = server.get("address")
                if isinstance(address, str):
                    if is_ip(address):
                        ip = address
                    else:
                        ip = resolve_to_ip(address)
                        if not ip:
                            return None, None

                    if not is_cloudflare_ip(ip):
                        ips.add(ip)

                    server["address"] = ip

            continue

        # vmess/vless : the newer formats that are more flattened with direct address in settings
        address = settings.get("address")
        if isinstance(address, str):
            if is_ip(address):
                ip = address
            else:
                ip = resolve_to_ip(address)
                if not ip:
                    return None, None

            if not is_cloudflare_ip(ip):
                ips.add(ip)

            settings["address"] = ip

        # trojan
        servers = settings.get("servers")
        if isinstance(servers, list):
            for server in servers:
                if isinstance(server, dict):
                    address = server.get("address")
                    if isinstance(address, str):
                        if is_ip(address):
                            ip = address
                        else:
                            ip = resolve_to_ip(address)
                            if not ip:
                                return None, None
                        if not is_cloudflare_ip(ip):
                            ips.add(ip)
                        server["address"] = ip

        # wireguard
        peers = settings.get("peers")
        if isinstance(peers, list):
            for peer in peers:
                if isinstance(peer, dict):
                    endpoint = peer.get("endpoint")
                    if isinstance(endpoint, str):
                        host_port = endpoint.split(":")
                        host = host_port[0]

                        if is_ip(host):
                            ip = host
                        else:
                            ip = resolve_to_ip(host)
                            if not ip:
                                return None, None

                        if not is_cloudflare_ip(ip):
                            ips.add(ip)

                        if len(host_port) > 1:
                            peer["endpoint"] = f"{ip}:{host_port[1]}"
                        else:
                            peer["endpoint"] = ip
                            
    # It's better to remove the direct rules in VPN mode
    if current_mode == "vpn":
        return list(ips), remove_direct_routes(patched_config)
    
    return list(ips), patched_config
    
##############################################################################

def is_cloudflare_ip(ip):
    """ Checks if an IP belongs to Cloudflare. """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in subnet for subnet in CLOUDFLARE_SUBNETS)
    except ValueError:
        return False

##############################################################################
    
def resolve_domains_vless(config: dict) -> dict:
    """
    (Extra function)
    Resolves outbound vnext domains (if any) to IPs.
    Here it ensures they are Cloudflare IPs, and if not,
    it uses a random fallback IP from a predefined list.
    """
    outbounds = config.get("outbounds", [])
    if not isinstance(outbounds, list):
        return config

    for outbound in outbounds:
        settings = outbound.get("settings")
        if not isinstance(settings, dict):
            continue

        vnext = settings.get("vnext")
        if not isinstance(vnext, list):
            continue

        for server in vnext:
            if not isinstance(server, dict):
                continue

            address = server.get("address")
            if not isinstance(address, str):
                continue

            try:
                ip = socket.gethostbyname(address)
                if is_cloudflare_ip(ip):
                    server["address"] = ip
                else:
                    if FALLBACK_IPS:
                        fallback = random.choice(list(FALLBACK_IPS))
                        print(f"Non-CF IP for {address} ({ip}) --> using fallback {fallback}")
                        server["address"] = fallback
                    else:
                        print(f"Non-CF IP for {address} and no fallback available.")
            except socket.gaierror:
                print(f"Failed to resolve {address}")

    return config

##############################################################################

def process_file(file_path: Path, output_path: Path):
    """ 
    Downloads the json config from a json sublink file,
    or checks if it is an Xray config itself. Processes
    the file using resolve_domains.
    """
    global ip_list
    try:
        with open(file_path, "r") as f:
            url = f.read().strip()
    except Exception as e:
        # The entry is not either a valid sublink or a valid json
        return 9 # Que to delete the entry

    # Check if the file itself is an Xray conf
    try:
        config = json.loads(url)
    except json.JSONDecodeError:
        print(f"Downloading from: {url}")
        config = download_json_from_url(url)
        if not config:
            return None

    ip_list, updated_config = resolve_domains(config)
    # If both were None, there was a problem in resolution
    if not ip_list and not updated_config:
        return None
    with open(output_path, "w") as f:
        json.dump(updated_config, f, indent=2)
    print(f"Saved config file to: {output_path}")
    return True

##############################################################################

def run_tun2proxy():
    global tun2proxy_pid
    global ip_list

    # Merge Cloudflare subnets with the server IPs--all to be bypassed
    ip_list.extend(str(net) for net in CLOUDFLARE_SUBNETS)

    # Bypass the extremely chatty mDNS as well
    ip_list.append("224.0.0.0/4")
    # Avoid routing loop as much as possible
    ip_list.append("127.0.0.0/8")

    # Since no process can get elavated from inside an appimage, 
    # necessary scripts and binaries must reside in a path outside.
    shutil.copy(os.path.join(appdir, "usr", "bin", "tun2proxy-bin"), os.path.join(temp_root, "usr", "bin"))

    # Create run_vpn.sh with the updated IPs to be bypassed
    write_run_vpn_sh(os.path.join(temp_root, "run_vpn.sh"), ip_list)
    # Make sure everything is executable
    os.chmod(os.path.join(temp_root, "usr", "bin", "tun2proxy-bin"), 0o755)

    cmd = ["pkexec", os.path.join(temp_root, "run_vpn.sh"), "start"]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        backend_procs.append(proc) # the run_vpn.sh process
        # run_vpn.sh will echo the pid of tun2proxy-bin
        stdout, stderr = proc.communicate(timeout=10)
        pid_str = stdout.strip()

        if pid_str.isdigit():
            tun2proxy_pid = int(pid_str)
        else:
            print("Failed to get PID:", stdout, stderr)
            return None

        return True
    except Exception as e:
        print(f"[tun2proxy] Failed to start: {e}")
        return None

##############################################################################  

def run_xray(config_file_path):
    global xray_pid
    if not os.path.isfile(config_file_path):
        print(f"[xray] Config not found: {config_file_path}")
        return
    cmd = [os.path.join(appdir, "usr/bin/xray-bin"), "run", "-c", config_file_path]

    try:
        log_file = open(xray_log_file, "a")
        proc = subprocess.Popen(cmd, stdout=log_file, stderr=log_file, shell=False)
        backend_procs.append(proc)
        # Store the PID for later termination
        xray_pid = proc.pid
        return True
    except Exception as e:
        print(f"[xray] Failed to start: {e}")
        return None

##############################################################################

class MainWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="GorzRay")
        self.set_border_width(10)
        self.set_default_size(800, 600)

        vbox = Gtk.VBox(spacing=10)
        self.add(vbox)

        self.connect("destroy", self.on_destroy)
        
        hbox = Gtk.HBox(spacing=5)
        vbox.pack_start(hbox, False, False, 0)

        self.combo = Gtk.ComboBoxText()
        hbox.pack_start(self.combo, True, True, 0)

        browse_button = Gtk.Button(label="Browse...")
        hbox.pack_start(browse_button, False, False, 0)
        browse_button.connect("clicked", self.on_browse_clicked)

        # Populate dropdown
        self.populate_recent_files()
        
        # Load the last selected sublink file
        last_file = load_last_selected_file()
        if last_file and last_file in self.recent_files:
            index = self.recent_files.index(last_file)
            self.combo.set_active(index)
        
        # Proxy/VPN toggle button
        self.toggle_button = Gtk.ToggleButton(label="Proxy Mode")
        self.toggle_button.connect("toggled", self.on_toggle_mode)
        vbox.pack_start(self.toggle_button, False, False, 0)

        # Connect/Disconnect button
        self.start_button = Gtk.Button(label="Connect")
        self.start_button.connect("clicked", self.on_start_stop)
        vbox.pack_start(self.start_button, False, False, 0)

        # Logs
        self.xray_log_view = self._create_log_area("Proxy Log")
        self.tun2proxy_log_view = self._create_log_area("VPN Log")
        vbox.pack_start(self.xray_log_view, True, True, 0)
        vbox.pack_start(self.tun2proxy_log_view, True, True, 0)

        self.running = False

        # Socket server start
        self._socket_thread()

        # flags for the logging threads
        self.log_threads = []

        # Tray icon
        self.init_tray()

        # Start live log updates for anything that is "print"ed
        self._start_log_thread(early_log_file, self.proxy_log_textview)

        # Wait a little bit for the start of logging thread of early_log_file
        time.sleep(0.1)
        print ("GorzRay is ready.\n")
        
    #**************************************************************

    def populate_recent_files(self):
        """ Populates the dropdown menu. """
        self.combo.remove_all()
        self.recent_files = load_recent_files()
        for path in self.recent_files:
            self.combo.append_text(path)
        if self.recent_files:
            self.combo.set_active(0)

    #**************************************************************

    def on_browse_clicked(self, button):
        dialog = Gtk.FileChooserDialog(
            title="Select the sublink text File or the Xray config",
            parent=self,
            action=Gtk.FileChooserAction.OPEN,
        )
        dialog.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OPEN, Gtk.ResponseType.OK
        )

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            selected_path = dialog.get_filename()
            save_selected_file(selected_path)
            self.populate_recent_files()

        dialog.destroy()

    #**************************************************************
    
    def on_toggle_mode(self, button):
        global current_mode
        if button.get_active():
            current_mode = "vpn"
            button.set_label("VPN Mode")
        else:
            current_mode = "proxy"
            button.set_label("Proxy Mode")

    #**************************************************************
        
    def on_start_stop(self, button):
        global current_mode
        global selected_file_path
        selected_file_path = self.combo.get_active_text()
        
        if not selected_file_path:
            print("No file selected.")
            return
        else:
            save_last_selected_file(selected_file_path)

        if not self.running:
            button.set_label("Connecting ...")
            button.set_sensitive(False)
            self.toggle_button.set_sensitive(False)
            threading.Thread(
                target=self._start_backend_thread,
                args=(selected_file_path, button),
                daemon=True
            ).start()

        else:
            button.set_label("Disconnecting ...")
            self.kill_processes()

    #**************************************************************
        
    def _create_log_area(self, title):
        frame = Gtk.Frame(label=title)
        textview = Gtk.TextView()
        textview.set_editable(False)
        textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        textview.set_monospace(True)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.add(textview)
        frame.add(scroll)
        setattr(self, f"{title.lower().replace(' ', '_')}_textview", textview)
        return frame

    #**************************************************************

    def _start_backend_thread(self, selected_file, button):

        res = process_file(selected_file, output_config_path)
        if not res:
            print("Failed to process the config file.")
            GLib.idle_add(button.set_sensitive, True)
            GLib.idle_add(self.toggle_button.set_sensitive, True)
            GLib.idle_add(button.set_label, "Connect")
            self.running = False
            return
        elif res == 9:
            print("The file is malformed or doesn't exist. Removing the entry ...")
            omit_selected_file(selected_file)
            GLib.idle_add(self.populate_recent_files)
            GLib.idle_add(button.set_sensitive, True)
            GLib.idle_add(self.toggle_button.set_sensitive, True)
            GLib.idle_add(button.set_label, "Connect")
            self.running = False
            return
        
        def start_proxy(config_path, button):
            proxy_state = run_xray(config_path)
            if not proxy_state:
                print("Failed to run xray.")
                GLib.idle_add(button.set_sensitive, True)
                GLib.idle_add(button.set_label, "Connect")
                self.running = False
            else:
                self._start_log_thread(xray_log_file, self.proxy_log_textview)
                GLib.idle_add(button.set_sensitive, True)
                GLib.idle_add(button.set_label, "Disconnect")
                self.running = True
                GLib.idle_add(self.hide)
                GLib.idle_add(self.update_tray)
            return False

        def wait_for_tun2proxy_and_start_xray(self, config_path, button):
            max_attempts = 5  # 10 seconds total
            attempt_counter = {"count": 0}
            def check_and_start():
                # subprocess.check_output(["pgrep", "tun2proxy-bin"])
                if psutil.pid_exists(tun2proxy_pid):
                    self._start_log_thread(tun_log_file, self.vpn_log_textview)
                    GLib.timeout_add(2000, lambda: start_proxy(config_path, button)) # add an extra 2 seconds
                    print("Tun2proxy has started. Starting Xray...")
                    return False  # stop checking
                else:
                    attempt_counter["count"] += 1
                    print("Waiting for tun2proxy to start...")

                    if attempt_counter["count"] >= max_attempts:
                        print("Timeout waiting for tun2proxy. Aborting.")
                        # Kill the pkexec dialog just in case
                        try:
                            p = subprocess.check_call(["killall", "-9", "pkexec"])
                            os.wait()
                        except Exception as e:
                            pass
                        self.running = False
                        GLib.idle_add(button.set_sensitive, True)
                        GLib.idle_add(button.set_label, "Connect")
                        GLib.idle_add(self.toggle_button.set_sensitive, True)
                        return False  # stop checking
                    return True  # continue checking

            GLib.timeout_add(2000, check_and_start)

        if current_mode == "vpn":
            vpn_state = run_tun2proxy()
            if not vpn_state:
                print("Failed to connect to VPN.")
                GLib.idle_add(button.set_sensitive, True)
                GLib.idle_add(button.set_label, "Connect")
                self.running = False
                return
            else:
                wait_for_tun2proxy_and_start_xray(self, output_config_path, button)
        else:
            start_proxy(output_config_path, button)

    #**************************************************************

    def kill_processes(self):
        global xray_pid
        global tun2proxy_pid

        if current_mode == "vpn":
            if psutil.pid_exists(tun2proxy_pid):
                vpn_running = True
            else:
                # Kill the pkexec dialog just in case
                try:
                    p = subprocess.check_call(["killall", "-9", "pkexec"])
                    os.wait()
                except Exception as e:
                    pass
                vpn_running = False
                
            if vpn_running:
                try:
                    cmd = ["pkexec", os.path.join(temp_root, "run_vpn.sh"), "stop", str(tun2proxy_pid)]
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
	                text=True
                    )
                    stdout, stderr = proc.communicate(timeout=10)
                    print("VPN disconnected.")
                    self._stop_log_thread(tun_log_file)
                except ProcessLookupError:
                    print(f"Process {tun2proxy_pid} already exited.")
                except Exception as e:
                    ## subprocess.run(["pkexec", "kill", "-9", str(tun2proxy_pid)])
                    # Although run_vpn.sh should have handled it, if it is still
                    # running, it's better to let the user take care of it,
                    # because of the following comment.
                    pass

            # Only kill Xray if tun2proxy has exited successfully,
            # otherwise it will leave the network state in limbo.
            # First, wait a little bit to allow the process to fully exit
            for _ in range(10):
                if not psutil.pid_exists(tun2proxy_pid):
                    break
                time.sleep(0.3) # 3 seconds in total
                
            if psutil.pid_exists(tun2proxy_pid):
                print("Could not disconnect the VPN. Try again, or manually kill tun2proxy-bin and unmount /etc/resolv.conf")
                self.start_button.set_label("Disconnect")
                self.start_button.set_sensitive(True)
                return

        # End our instance of xray
        if psutil.pid_exists(xray_pid):
            try:
                os.kill(xray_pid, signal.SIGINT)
                os.waitpid(xray_pid, 0)
            except ProcessLookupError:
                print(f"Xray process {xray_pid} already exited.")
            except Exception as e:
                os.kill(xray_pid, signal.SIGKILL)
                os.waitpid(xray_pid, 0)

            self._stop_log_thread(xray_log_file)
            self.running = False
            self.start_button.set_label("Connect")
            self.start_button.set_sensitive(True)
            self.toggle_button.set_sensitive(True)
    
            GLib.idle_add(self.update_tray)    
            print("Proxy disconnected.")
            
    #**************************************************************

    def _start_log_thread(self, filepath, textview):
        stop_flag = threading.Event()

        def tail_log():
            buf = textview.get_buffer()
            last_inode = None
            f = None

            while not stop_flag.is_set():
                try:
                    stat = os.stat(filepath)
                    if last_inode != stat.st_ino:
                        if f:
                            f.close()
                        f = open(filepath, "r")
                        f.seek(0, os.SEEK_END)
                        last_inode = stat.st_ino

                    line = f.readline()
                    if line:
                        GLib.idle_add(self._append_text, buf, line, textview)
                    else:
                        time.sleep(0.5)

                except FileNotFoundError:
                    if f:
                        f.close()
                        f = None
                    last_inode = None
                    time.sleep(1)

            if f:
                f.close()

        thread = threading.Thread(target=tail_log, daemon=True)
        self.log_threads.append({
            "thread": thread,
            "stop_flag": stop_flag,
            "filepath": filepath
        })
        thread.start()    

    #**************************************************************

    def _append_text(self, buf, text, textview):
        buf.insert(buf.get_end_iter(), text)
        # Scroll to the end after inserting text
        mark = buf.create_mark(None, buf.get_end_iter(), True)
        textview.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)

    #**************************************************************

    def _stop_log_thread(self, filepath):
        for entry in self.log_threads:
            if entry["filepath"] == filepath:
                entry["stop_flag"].set()
                entry["thread"].join(timeout=1)

        # Remove stopped threads from the list
        self.log_threads = [
            entry for entry in self.log_threads if entry["filepath"] != filepath
        ]    

    #**************************************************************

    def _socket_thread(self):
        def socket_server():
            if os.path.exists(SOCKET_PATH):
                os.remove(SOCKET_PATH)
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(SOCKET_PATH)
            server.listen(1)
            os.chmod(SOCKET_PATH, 0o600)
            while True:
                conn, _ = server.accept()
                with conn:
                    data = conn.recv(1024).decode().strip()
                    if data in ("connect", "disconnect"):
                        if self.combo.get_active_text():
                            GLib.idle_add(self.on_start_stop, self.start_button)
                            conn.sendall(b"Connect/Disconnect: OK\n")
                    elif data == "setvpn":
                        if self.toggle_button.get_sensitive():
                            GLib.idle_add(self.toggle_button.set_active, True)
                            GLib.idle_add(self.on_toggle_mode, self.toggle_button)
                            conn.sendall(b"Set to VPN mode: OK\n")
                    elif data == "setproxy":
                        if self.toggle_button.get_sensitive():
                            GLib.idle_add(self.toggle_button.set_active, False)
                            GLib.idle_add(self.on_toggle_mode, self.toggle_button)
                            conn.sendall(b"Set to Proxy mode: OK\n")
                    else:
                        conn.sendall(b"Not defined.\n")
                        
        threading.Thread(target=socket_server, daemon=True).start()
        
    #**************************************************************
    
    def on_destroy(self, widget):
        print("Cleaning up any remaining processes...")
        self.tray_icon.stop()
        self.kill_processes()
        shutil.rmtree(TMPDIR)
        Gtk.main_quit()

    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    def init_tray(self):
        # Define dynamic labels for tray
        self.tray_toggle_item = pystray.MenuItem(
            lambda item: "Disconnect" if self.running else "Connect",
            self._tray_toggle_connect
        )

        self.tray_window_item = pystray.MenuItem(
            lambda item: "Hide Window" if self.get_visible() else "Show Window",
            self._toggle_window_visibility
        )

        self.tray_icon = pystray.Icon(
            "GorzRay",
            icon_image,
            "GorzRay",
            menu=pystray.Menu(
                self.tray_window_item,
                self.tray_toggle_item,
                pystray.MenuItem("Exit", self._tray_exit),
            )
        )

        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        
    def _toggle_window_visibility(self):
        if self.get_visible():
            self.hide()
        else:
            self.show_all()

    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            
    def _tray_toggle_connect(self):
        if self.start_button.get_sensitive():
            GLib.idle_add(self.on_start_stop, self.start_button)

    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++            

    def _tray_exit(self):
        self.tray_icon.stop()
        self.kill_processes()
        shutil.rmtree(TMPDIR)
        Gtk.main_quit()

    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        
    def update_tray(self):
        title_text = ""
        gtk_label = self.start_button.get_label()
        # Update the menu first
        self.tray_icon.update_menu()

        # Update the icon and the title/notification text
        # On both Wayland and X11 the notification works well in my testing.
        # However, the documentation advises further checks On X11: if self.tray_icon.HAS_NOTIFICATION
        if self.running and current_mode == "proxy" and gtk_label == "Disconnect":
            self.tray_icon.icon = icon_image_proxy
            if self.tray_icon.HAS_NOTIFICATION:
                self.tray_icon.notify(f"Proxy: {os.path.basename(selected_file_path)}","Connected")
            title_text = f"Connected to Proxy: {os.path.basename(selected_file_path)}"
        elif self.running and current_mode == "vpn" and gtk_label == "Disconnect":
            self.tray_icon.icon = icon_image_vpn
            if self.tray_icon.HAS_NOTIFICATION:
                self.tray_icon.notify(f"VPN: {os.path.basename(selected_file_path)}","Connected")
            title_text = f"Connected to VPN: {os.path.basename(selected_file_path)}"
        else:
            self.tray_icon.icon = icon_image
            if selected_file_path:
                if self.tray_icon.HAS_NOTIFICATION:
                    self.tray_icon.notify(f"from: {os.path.basename(selected_file_path)}","Disconnected")
            title_text = f"GorzRay: ready"
        # Update the title
        self.tray_icon.title = title_text

##############################################################################

def write_run_vpn_sh(path, ip_list):
    
    bypass_lines = '\n'.join([f'      --bypass {ip} \\' for ip in sorted(ip_list)])

    script = f"""#!/bin/bash

set -e

APPDIR="$(dirname "$(readlink -f "$0")")"

LOGFILE="{tun_log_file}" # $APPDIR/gorzray_tun2proxy.log
chmod 644 "$LOGFILE"

start_vpn() {{
    echo "Connecting in VPN Mode ..." >> "$LOGFILE"

    # Your server IP should already be listed here, 
    # but if it is from an unsupported protocol, 
    # add your target IP to the bypass list manually here.
    # And if necessary, change Xray socks server.
    exec "$APPDIR/usr/bin/tun2proxy-bin" \\
{bypass_lines}
      --setup -6 \\
      --proxy socks5://127.0.0.1:{socks_port} \\
      --dns virtual \\
      --exit-on-fatal-error \\
      -v info > "$LOGFILE" 2>&1 &

    # Return tun2proxy-bin pid and detach from Python
    echo "$!"
    disown
}}

stop_vpn() {{
    PID="$1"

    if [[ -z "$PID" ]]; then
        echo "Usage: $0 stop <PID>"
        exit 1
    fi

    if ! ps -p "$PID" > /dev/null 2>&1; then
        echo "Process $PID not found"
        exit 1
    fi

    CMD=$(ps -p "$PID" -o comm= 2>/dev/null)
    if [[ "$CMD" != "tun2proxy-bin" ]]; then
        echo "Process $PID is not tun2proxy-bin"
        exit 1
    fi

    kill -TERM "$PID"
    echo "Sent SIGTERM to tun2proxy-bin (PID $PID)"

    # Wait for the process to exit (max 5 seconds)
    for i in {{1..10}}; do
        sleep 0.5
        if ! ps -p "$PID" > /dev/null 2>&1; then
            echo "Process $PID has exited"
            exit 0
        fi
    done

    # force majeure
    echo "Process $PID did not exit, sending SIGKILL"
    kill -KILL "$PID"
    umount -l /etc/resolv.conf
    exit 0
}}

case "$1" in
    start)
        start_vpn
        ;;
    stop)
        stop_vpn "$2"
        ;;
    *)
        echo "Usage: $0 {{start|stop <PID>}}"
        exit 1
        ;;
esac
"""

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(script)
    os.chmod(path, 0o755)

##############################################################################

def write_polkit_files(parent_path):

    policy_file = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd">
<policyconfig>
  <vendor>GorzRay VPN Mode</vendor>
  <vendor_url>https://github.com/ketetefid/GorzRay</vendor_url>

  <action id="org.gorzray.vpn">
    <description>Allows passwordless authentication of VPN Mode in GorzRay</description>
    <message>Authentication is granted to run GorzRay</message>
    <icon_name>preferences-system</icon_name>

    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>

    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
    <annotate key="org.freedesktop.policykit.exec.path">{temp_root}/run_vpn.sh</annotate>
  </action>
</policyconfig>
"""

    rule_file = f"""polkit.addRule(function(action, subject) {{
    if (action.id == "org.gorzray.vpn") {{
        return polkit.Result.YES;
    }}
}});
"""
    
    script = f"""#!/bin/bash

# Installs Polkit files for passwordless authentication in VPN mode
set -e

FILEDIR="{temp_root}" # must match temp_root in the Python code

cp "$FILEDIR/gorzray.policy" /usr/share/polkit-1/actions/gorzray.policy && chmod 644 /usr/share/polkit-1/actions/gorzray.policy && echo "policy file was installed."

cp "$FILEDIR/77-gorzray.rules" /etc/polkit-1/rules.d/77-gorzray.rules && chmod 644 /etc/polkit-1/rules.d/77-gorzray.rules && echo "rule file was installed."

exit 0
"""

    os.makedirs(os.path.dirname(parent_path), exist_ok=True)

    files = {
        os.path.join(parent_path, "install_polkit_files.sh"): (script, 0o755),
        os.path.join(parent_path, "gorzray.policy"): (policy_file, 0o644),
        os.path.join(parent_path, "77-gorzray.rules"): (rule_file, 0o644),
    }

    for target_path, (content, mode) in files.items():
        with open(target_path, "w") as f:
            f.write(content)
        os.chmod(target_path, mode)
        
##############################################################################
    
def install_polkit_files():
    print("Installing Polkit files for activating passwordless VPN mode.")

    target_policy_path = "/usr/share/polkit-1/actions/gorzray.policy"
    target_rule_path = "/etc/polkit-1/rules.d/77-gorzray.rules"

    try:
        # Create polkit files in {temp_root}
        write_polkit_files (temp_root)
        print("This operation requires root privileges.")
        subprocess.run(["pkexec", os.path.join(temp_root, "install_polkit_files.sh")], check=True)

        print("PolicyKit files installed successfully into:")
        print(target_policy_path)
        print(target_rule_path)
        print("You may need to restart your session or polkit daemon/agent.")
    except Exception as e:
        print(f"Installation failed: {e}")
        sys.exit(1)

##############################################################################       

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--minimized", action="store_true", help="Start the app minimized (only tray icon)")
    parser.add_argument("--connect-proxy", action="store_true", help="Connect to the last entry in Proxy mode automatically with startup")
    parser.add_argument("--connect-vpn", action="store_true", help="Connect to the last entry in VPN mode automatically with startup")
    parser.add_argument("--install-policy", action="store_true", help="Install a set of policy and rule files for use with Polkit for passwordless authentication in VPN mode")
    args = parser.parse_args()

    if args.install_policy:
        install_polkit_files()
        return
    
    win = MainWindow()
    if not args.minimized:
        win.show_all()

    win.update_tray()

    if args.connect_proxy:
        if args.connect_vpn:
            pass
        elif win.combo.get_active_text():
            print("Connecting in Proxy Mode...")
            GLib.idle_add(win.on_start_stop, win.start_button)

    if args.connect_vpn:
        if win.combo.get_active_text():
            print("Connecting in VPN Mode...")
            GLib.idle_add(win.toggle_button.set_active, True)
            GLib.idle_add(win.on_toggle_mode, win.toggle_button)
            GLib.idle_add(win.on_start_stop, win.start_button)

    Gtk.main()
    
if __name__ == "__main__":
    main()
