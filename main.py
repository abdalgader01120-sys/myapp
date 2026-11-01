from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.clock import Clock
import threading
import socket
import ssl
import time
import os
import datetime
import sys
import re
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

LISTEN_IP = "127.0.0.1"
CONNECT_PORT = 8444
CERTS_DIR = "certs"
VPS_IP = "2a00:b6e0:1:50:1::1" 
VPS_PORT = 8080                   

TARGET_DOMAINS = (
    "whatsapp.com", "whatsapp.net", "wa.me", "fbcdn.net",
    "facebook.com", "fb.com", "fb.me", "facebook.net", "fbsbx.com",
    "instagram.com", "cdninstagram.com", "meta.com", "meta.ai",
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com"
)
WHATSAPP_IPS = ["57.144.69.32", "57.144.121.32", "102.132.97.54"]

class ProxyApp(App):
    def build(self):
        self.title = "Jaddo MITM Proxy"
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.status_label = Label(text="Status: Stopped", font_size='18sp', size_hint_y=None, height=50)
        layout.add_widget(self.status_label)
        self.toggle_btn = Button(text="Start Proxy", font_size='22sp', background_color=(0, 1, 0, 1), size_hint_y=None, height=70)
        self.toggle_btn.bind(on_press=self.toggle_proxy)
        layout.add_widget(self.toggle_btn)
        self.log_box = TextInput(text='', readonly=True, font_size='12sp', background_color=(0.1, 0.1, 0.1, 1), foreground_color=(0,1,0,1))
        scroll = ScrollView()
        scroll.add_widget(self.log_box)
        layout.add_widget(scroll)
        self.is_running = False
        self.server_socket = None
        self.app_dir = self.user_data_dir
        self.ca_cert_path = os.path.join(self.app_dir, "cert.pem")
        self.ca_key_path = os.path.join(self.app_dir, "key.pem")
        self.certs_dir = os.path.join(self.app_dir, CERTS_DIR)
        self.ssl_ctx_cache = {}
        self.ctx_lock = threading.Lock()
        self.generate_ca_if_needed()
        return layout

    def log(self, msg): Clock.schedule_once(lambda dt: self.append_log(msg))
    def append_log(self, msg): self.log_box.text += msg + "\n"; self.log_box.cursor = (0, 0)

    def generate_ca_if_needed(self):
        if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path): return
        self.log("[*] Generating CA...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Jaddo Proxy CA")])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc)).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
        with open(self.ca_cert_path, "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(self.ca_key_path, "wb") as f: f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        self.log(f"[+] CA saved: {self.ca_cert_path}")

    def toggle_proxy(self, instance):
        if not self.is_running:
            self.is_running = True
            self.toggle_btn.text = "Stop Proxy"
            self.toggle_btn.background_color = (1, 0, 0, 1)
            self.status_label.text = f"Running on {LISTEN_IP}:{CONNECT_PORT}"
            threading.Thread(target=self.proxy_server_loop, daemon=True).start()
        else:
            self.is_running = False
            if self.server_socket: 
                try: self.server_socket.close()
                except: pass
            self.toggle_btn.text = "Start Proxy"
            self.toggle_btn.background_color = (0, 1, 0, 1)
            self.status_label.text = "Stopped"

    def get_server_ctx(self, host):
        with self.ctx_lock:
            if host in self.ssl_ctx_cache: return self.ssl_ctx_cache[host]
            os.makedirs(self.certs_dir, exist_ok=True)
            c_path = os.path.join(self.certs_dir, f"{host}.crt")
            k_path = os.path.join(self.certs_dir, f"{host}.key")
            if not os.path.exists(c_path):
                with open(self.ca_cert_path, "rb") as f: ca_cert = x509.load_pem_x509_certificate(f.read())
                with open(self.ca_key_path, "rb") as f: ca_key = serialization.load_pem_private_key(f.read(), password=None)
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                now = datetime.datetime.now(datetime.timezone.utc)
                cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])).issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False).sign(ca_key, hashes.SHA256()))
                with open(c_path, "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
                with open(k_path, "wb") as f: f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=c_path, keyfile=k_path)
            ctx.set_alpn_protocols(["http/1.1"])
            self.ssl_ctx_cache[host] = ctx
            return ctx

    def _mk_remote_ctx(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx

    def is_target(self, host):
        h = host.lower().rstrip(".")
        return any(h == s or h.endswith("." + s) for s in TARGET_DOMAINS)

    def connect_to_vps(self, th, tp):
        sock = socket.create_connection((VPS_IP, VPS_PORT), timeout=10.0)
        req = f"CONNECT {th}:{tp} HTTP/1.1\r\nHost: {th}:{tp}\r\n\r\n".encode()
        sock.sendall(req)
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk: break
            resp += chunk
        if b"200" not in resp:
            sock.close()
            raise ConnectionError("VPS refused")
        return sock

    def handle_client(self, client_sock, addr):
        host = "unknown"; tls_client = None; tls_remote = None; remote_sock = None
        try:
            client_sock.settimeout(10.0)
            req = client_sock.recv(4096)
            if not req or not req.startswith(b"CONNECT "): return
            host = req.split(b" ")[1].split(b":")[0].decode()
            if not self.is_target(host):
                client_sock.close(); return
            self.log(f"REQ: {host}")
            if "whatsapp" in host or "fbcdn" in host or "facebook" in host:
                real_ip = WHATSAPP_IPS[int(time.time()) % len(WHATSAPP_IPS)]
                sni = "v.whatsapp.net"   
            else:
                real_ip = host; sni = host
            try:
                if "whatsapp" not in host and "fbcdn" not in host and "facebook" not in host:
                    remote_sock = self.connect_to_vps(real_ip, 443)
                else:
                    remote_sock = socket.create_connection((real_ip, 443), timeout=10.0)
            except Exception:
                self.log(f"ERR {host} (TCP)")
                client_sock.close(); return
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            client_sock.settimeout(None)
            try:
                tls_client = self.get_server_ctx(host).wrap_socket(client_sock, server_side=True)
                client_sock = None 
            except:
                remote_sock.close(); return
            try:
                remote_sock.settimeout(10.0)
                tls_remote = self._mk_remote_ctx().wrap_socket(remote_sock, server_hostname=sni, do_handshake_on_connect=False)
                remote_sock = None 
                tls_remote.do_handshake()
                tls_remote.settimeout(None)
                self.log(f"OK: {host}")
            except Exception:
                self.log(f"ERR {host} (TLS)")
                if tls_client: tls_client.close()
                return
            req_data = b""
            while b"\r\n\r\n" not in req_data:
                chunk = tls_client.recv(4096)
                if not chunk: break
                req_data += chunk
            tls_remote.sendall(req_data)
            resp_head = b""
            while b"\r\n\r\n" not in resp_head:
                chunk = tls_remote.recv(4096)
                if not chunk: break
                resp_head += chunk
            tls_client.sendall(resp_head)
            def pipe(src, dst):
                try:
                    while True:
                        data = src.recv(65536)
                        if not data: break
                        dst.sendall(data)
                except: pass
                finally:
                    try: dst.shutdown(socket.SHUT_WR)
                    except: pass
            t1 = threading.Thread(target=pipe, args=(tls_client, tls_remote))
            t2 = threading.Thread(target=pipe, args=(tls_remote, tls_client))
            t1.start(); t2.start(); t1.join(); t2.join()
        except Exception: pass
        finally:
            if tls_client: 
                try: tls_client.close()
                except: pass
            elif client_sock:
                try: client_sock.close()
                except: pass
            if tls_remote: 
                try: tls_remote.close()
                except: pass
            elif remote_sock:
                try: remote_sock.close()
                except: pass

    def proxy_server_loop(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((LISTEN_IP, CONNECT_PORT))
            self.server_socket.listen(200)
            self.log(f"[+] Proxy Started: {LISTEN_IP}:{CONNECT_PORT}")
            while self.is_running:
                try:
                    client_sock, addr = self.server_socket.accept()
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()
                except OSError: break
        except Exception as e: self.log(f"Server Error: {e}")

if __name__ == '__main__':
    ProxyApp().run()
