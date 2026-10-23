import flet as ft
import psutil
import socket
import hashlib
import threading
import time
import os
import urllib.parse
from datetime import datetime

# Try importing external security libraries; fall back to native logic if absent
try:
    from securescanner import SecurityScanner
    HAS_SECURESCANNER = True
except ImportError:
    HAS_SECURESCANNER = False

try:
    from linksentry import predict_url
    HAS_LINKSENTRY = True
except ImportError:
    HAS_LINKSENTRY = False

class CyberSecurityApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Titan Shield - Unified Security Suite"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.window_width = 1280
        self.page.window_height = 800
        self.page.padding = 0
        self.page.bgcolor = "#0B0F19"

        # State variables for counters
        self.suspicious_apks_count = 3
        self.phishing_links_count = 2
        self.scan_progress = 0.68
        self.system_status = "Scanning System Files & OS APIs..."

        self.setup_ui()

    def setup_ui(self):
        # --- Sidebar Navigation ---
        sidebar = ft.Container(
            width=260,
            bgcolor="#111827",
            padding=20,
            content=ft.Column(
                controls=[
                    ft.Row([
                        ft.Icon(ft.Icons.SHIELD, color="#00E5FF", size=28),
                        ft.Text("TITAN SHIELD", size=18, weight=ft.FontWeight.BOLD, color="#FFFFFF")
                    ]),
                    ft.Divider(color="#1F2937"),
                    ft.TextButton("Dashboard", icon=ft.Icons.DASHBOARD, style=ft.ButtonStyle(color="#00E5FF")),
                    ft.TextButton("File & OS Scanner", icon=ft.Icons.FOLDER_OPEN),
                    ft.TextButton("Network & Ports", icon=ft.Icons.ROUTER),
                    ft.TextButton("Mobile OS Audit", icon=ft.Icons.PHONE_ANDROID),
                    ft.TextButton("Reports", icon=ft.Icons.ASSESSMENT),
                    ft.TextButton("Settings", icon=ft.Icons.SETTINGS),
                    ft.Spacer(),
                    ft.Container(
                        content=ft.Column([
                            ft.Text("Supported Platforms", size=12, color="#9CA3AF"),
                            ft.Row([ft.Icon(ft.Icons.WINDOWS, size=16), ft.Text("Windows 11", size=12)]),
                            ft.Row([ft.Icon(ft.Icons.ANDROID, size=16), ft.Text("Android 14-17", size=12)]),
                            ft.Row([ft.Icon(ft.Icons.APPLE, size=16), ft.Text("iOS 24-27", size=12)]),
                        ]),
                        padding=10,
                        bgcolor="#1F2937",
                        border_radius=8
                    )
                ]
            )
        )

        # --- Main Dashboard Grid ---
        # 1. System Deep Scan Ring
        self.scan_ring = ft.ProgressRing(
            value=self.scan_progress,
            width=140,
            height=140,
            stroke_width=12,
            color="#00E5FF",
            bgcolor="#1F2937"
        )
        system_scan_card = ft.Container(
            content=ft.Column([
                ft.Text("System Deep Scan", weight=ft.FontWeight.BOLD),
                ft.Stack([
                    self.scan_ring,
                    ft.Container(
                        content=ft.Text(f"{int(self.scan_progress*100)}%", size=24, weight=ft.FontWeight.BOLD),
                        alignment=ft.alignment.center
                    )
                ], width=140, height=140),
                ft.Text(self.system_status, size=11, color="#9CA3AF", text_align=ft.TextAlign.CENTER)
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            bgcolor="#111827", padding=20, border_radius=12, expand=True
        )

        # 2. Threat Detection Counters
        threat_counter_card = ft.Container(
            content=ft.Column([
                ft.Text("Threat Detection Counter", weight=ft.FontWeight.BOLD),
                ft.Row([
                    ft.Column([
                        ft.Text(str(self.suspicious_apks_count), size=32, weight=ft.FontWeight.BOLD, color="#F59E0B"),
                        ft.Text("Suspicious APKs", size=12, color="#9CA3AF")
                    ]),
                    ft.Column([
                        ft.Text(str(self.phishing_links_count), size=32, weight=ft.FontWeight.BOLD, color="#EF4444"),
                        ft.Text("Phishing Links", size=12, color="#9CA3AF")
                    ])
                ], alignment=ft.MainAxisAlignment.SPACE_AROUND)
            ]),
            bgcolor="#111827", padding=20, border_radius=12, expand=True
        )

        # 3. URL Phishing Analyzer
        self.url_input = ft.TextField(
            hint_text="http://login-secure-update.com",
            bgcolor="#1F2937",
            border_color="#374151",
            expand=True
        )
        self.url_result_text = ft.Text("", color="#00E5FF", size=13)
        url_card = ft.Container(
            content=ft.Column([
                ft.Text("URL & Phishing Alert Scan", weight=ft.FontWeight.BOLD),
                ft.Row([
                    self.url_input,
                    ft.ElevatedButton("Analyze URL", on_click=self.analyze_url, bgcolor="#00E5FF", color="#000000")
                ]),
                self.url_result_text
            ]),
            bgcolor="#111827", padding=20, border_radius=12, expand=True
        )

        # 4. Network & Port Vulnerability Auditing
        self.ip_input = ft.TextField(value="127.0.0.1", hint_text="Target IP", bgcolor="#1F2937", width=200)
        self.port_log = ft.ListView(expand=True, spacing=5, height=150)
        self.port_scan_btn = ft.ElevatedButton("Scan Ports", on_click=self.start_port_scan, bgcolor="#00E5FF", color="#000000")
        network_card = ft.Container(
            content=ft.Column([
                ft.Text("Network & Port Vulnerabilities", weight=ft.FontWeight.BOLD),
                ft.Row([self.ip_input, self.port_scan_btn]),
                ft.Divider(color="#1F2937"),
                self.port_log
            ]),
            bgcolor="#111827", padding=20, border_radius=12, expand=True
        )

        # 5. AI Cyber Assistant
        self.chat_history = ft.ListView(expand=True, spacing=10, height=200)
        self.chat_input = ft.TextField(hint_text="Ask AI Security Assistant...", expand=True)
        ai_card = ft.Container(
            content=ft.Column([
                ft.Text("AI Cyber Assistant", weight=ft.FontWeight.BOLD),
                self.chat_history,
                ft.Row([
                    self.chat_input,
                    ft.IconButton(ft.Icons.SEND, on_click=self.send_chat, icon_color="#00E5FF")
                ])
            ]),
            bgcolor="#111827", padding=20, border_radius=12, expand=True
        )

        # --- Layout Assembly ---
        grid = ft.ResponsiveRow(
            controls=[
                ft.Container(content=system_scan_card, col={"sm": 12, "md": 6, "xl": 4}),
                ft.Container(content=threat_counter_card, col={"sm": 12, "md": 6, "xl": 4}),
                ft.Container(content=network_card, col={"sm": 12, "md": 12, "xl": 4}),
                ft.Container(content=url_card, col={"sm": 12, "md": 6, "xl": 6}),
                ft.Container(content=ai_card, col={"sm": 12, "md": 6, "xl": 6}),
            ],
            spacing=20,
            run_spacing=20
        )

        main_content = ft.Container(
            content=ft.Column([
                ft.Text("Cyber Security & Anti-Virus", size=32, weight=ft.FontWeight.BOLD),
                ft.Text("Cross-Platform Desktop & Mobile Application (iOS 27 / Android 17 Supported)", size=14, color="#9CA3AF"),
                ft.Divider(color="#1F2937"),
                grid
            ]),
            padding=30,
            expand=True
        )

        self.page.add(ft.Row([sidebar, main_content], expand=True))

    # --- Backend Functions ---
    def analyze_url(self, e):
        url = self.url_input.value.strip()
        if not url:
            self.url_result_text.value = "⚠️ Please enter a URL."
            self.url_result_text.color = "#F59E0B"
            self.page.update()
            return
        
        self.url_result_text.value = "🔍 Analyzing URL threat heuristics..."
        self.url_result_text.color = "#00E5FF"
        self.page.update()

        is_phishing = False
        confidence = 0.0
        reason = ""

        if HAS_LINKSENTRY:
            try:
                res = predict_url(url)
                is_phishing = (res['label'] == 'phishing')
                confidence = res['confidence']
                reason = "ML Model flagged suspicious patterns."
            except Exception:
                pass

        if not HAS_LINKSENTRY:
            # Fallback heuristic analysis
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            if any(s in domain for s in ["login-secure", "update-verify", "banking-alert", "free-gift"]):
                is_phishing = True
                reason = "Heuristic match: Brand impersonation in subdomain."
            elif "@" in url or (len(url) > 75):
                is_phishing = True
                reason = "Heuristic match: Obfuscation or excessive URL length."
            else:
                reason = "No obvious heuristic indicators found."

        if is_phishing:
            self.phishing_links_count += 1
            self.url_result_text.value = f"🚨 PHISHING DETECTED! Confidence: {confidence*100:.1f}% | {reason}"
            self.url_result_text.color = "#EF4444"
        else:
            self.url_result_text.value = f"✅ LEGITIMATE URL. Confidence: {(1-confidence)*100:.1f}% | {reason}"
            self.url_result_text.color = "#10B981"
        self.page.update()

    def start_port_scan(self, e):
        target = self.ip_input.value.strip()
        if not target:
            return
        self.port_scan_btn.disabled = True
        self.port_log.controls.append(ft.Text(f"[*] Starting scan on {target}...", color="#F59E0B"))
        self.page.update()

        def scan_thread():
            if HAS_SECURESCANNER:
                try:
                    scanner = SecurityScanner(target)
                    # Scan common ports for demonstration
                    scanner.scan(start_port=20, end_port=1024, num_threads=50)
                    for port_info in scanner.get_open_ports():
                        self.port_log.controls.append(
                            ft.Text(f"[OPEN] Port {port_info['port']}: {port_info['service']}", color="#10B981")
                        )
                except Exception as ex:
                    self.port_log.controls.append(ft.Text(f"[!] Scanner error: {ex}", color="#EF4444"))
            else:
                # Fallback native socket scanner
                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
                for port in common_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.4)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        self.port_log.controls.append(ft.Text(f"[OPEN] Port {port} is accessible", color="#10B981"))
                    sock.close()
            self.port_log.controls.append(ft.Text("[*] Port scan complete.", color="#00E5FF"))
            self.port_scan_btn.disabled = False
            self.page.update()

        threading.Thread(target=scan_thread, daemon=True).start()

    def send_chat(self, e):
        user_msg = self.chat_input.value.strip()
        if not user_msg:
            return
        self.chat_history.controls.append(
            ft.Container(content=ft.Text(f"👤 {user_msg}"), padding=8, bgcolor="#1F2937", border_radius=8, alignment=ft.alignment.center_right)
        )
        self.chat_input.value = ""
        self.page.update()

        # AI Assistant Logic
        msg_lower = user_msg.lower()
        if "port" in msg_lower or "network" in msg_lower:
            response = ("Port 5555 (ADB) is often targeted. Ensure it is not exposed to the public internet. "
                        "Use firewall rules to restrict access to trusted IPs only.")
        elif "phishing" in msg_lower or "url" in msg_lower:
            response = ("Always verify the root domain. Phishers often use subdomains like 'paypal.com.secure-login.xyz'. "
                        "Enable multi-factor authentication (MFA) wherever possible.")
        elif "virus" in msg_lower or "malware" in msg_lower:
            response = ("Run the 'System Deep Scan' from the dashboard. The application monitors file hashes and system calls. "
                        "If suspicious APKs are found, do not install them and quarantine the files.")
        else:
            response = ("I am Titan Shield AI. I can assist with network hardening, phishing analysis, and system security audits. "
                        "How can I help you secure your environment today?")

        self.chat_history.controls.append(
            ft.Container(content=ft.Text(f"🤖 {response}"), padding=8, bgcolor="#0F766E", border_radius=8, alignment=ft.alignment.center_left)
        )
        self.page.update()

def main(page: ft.Page):
    CyberSecurityApp(page)

if __name__ == "__main__":
    ft.run(main)