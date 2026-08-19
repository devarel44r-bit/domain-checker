import socket
import requests

domain = input("Masukkan domain: ").strip()

domain = domain.replace("https://", "")
domain = domain.replace("http://", "")
domain = domain.replace("/", "")

print("\n==============================")
print(f"DOMAIN CHECKER: {domain}")
print("==============================")

# CEK DNS
try:
    ip = socket.gethostbyname(domain)
    print("[OK] DNS aktif")
    print(f"[OK] IP Address : {ip}")
except socket.gaierror:
    print("[ERROR] DNS tidak ditemukan")

# CEK HTTP
try:
    response = requests.get(
        f"http://{domain}",
        timeout=10,
        allow_redirects=True
    )

    print(f"[HTTP] Status    : {response.status_code}")
    print(f"[HTTP] Final URL : {response.url}")

except requests.RequestException as error:
    print(f"[ERROR] HTTP gagal: {error}")

# CEK HTTPS
try:
    response = requests.get(
        f"https://{domain}",
        timeout=10,
        allow_redirects=True
    )

    print(f"[HTTPS] Status    : {response.status_code}")
    print(f"[HTTPS] Final URL : {response.url}")

except requests.RequestException as error:
    print(f"[ERROR] HTTPS gagal: {error}")

print("==============================")