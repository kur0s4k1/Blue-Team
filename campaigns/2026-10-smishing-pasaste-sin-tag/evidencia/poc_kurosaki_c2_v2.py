#!/usr/bin/env python3
# PoC de investigacion independiente: interactuar con el C2 del kit
# "Pasaste sin TAG" como victima ficticia, enviar datos falsos y observar
# los comandos del operador descifrados. NO usa datos reales.
import ssl, json, base64, os, random, string, urllib.request, urllib.error
import websocket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "peasastesintag.sbs"
BASE = f"https://{HOST}/6STusqEv"
CFIP = "190.44.5.5"  # IP sintetica aleatoria de prueba para el cloaking (no de una victima ni del analista)
UA = ("Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
COOKIE = ("_entry_session=JIEYOUTEMPLATE-20260906182151-4A0T%3A"
          "1791820844.5aff086c67918b7da8bd9435610b82db")
ENC_KEY_HEX = "4639e531772f003eeceecc0f29cef6f3cf879a1376b807e9cd093e200111ef27"
TEMPLATE = "JIEYOUTEMPLATE-20260906182151-4A0T"
WS_TOKEN = "eSDJOKGskskaklHUGF45IOJIOSAsjjkjnklgSIGhjksdIHIOGFA23SDKKsdhjg"
CID = "u_q9v2ie6z49nmv5fylqh"   # usuario ligado al token/sesion (autoritativo)

def b64(b): return base64.b64encode(b).decode()
def hx2b(h): return bytes.fromhex(h)

def http_get(path):
    req = urllib.request.Request(f"https://{HOST}{path}", headers={
        "CF-Connecting-IP": CFIP, "X-Forwarded-For": CFIP,
        "User-Agent": UA, "Cookie": COOKIE, "Referer": BASE + "/",
        "Accept": "application/json",
    })
    try:
        r = urllib.request.urlopen(req, timeout=15, context=ssl._create_unverified_context())
        return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return -1, str(e)

def load_pubkey(pem): return serialization.load_pem_public_key(pem.encode())

def enc_payload(pubkey, payload):
    key = os.urandom(32); iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(payload).encode(), None)
    wrapped = pubkey.encrypt(key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    return {"key": b64(wrapped), "iv": b64(iv), "data": b64(ct)}

def decrypt_static(payload):
    try:
        if not isinstance(payload, dict): return None
        e = payload.get("e"); iv = payload.get("iv")
        if not e or not iv: return None
        pt = AESGCM(hx2b(ENC_KEY_HEX)).decrypt(hx2b(iv), hx2b(e), None)
        return json.loads(pt.decode())
    except Exception as ex:
        return f"<decrypt fail: {ex}>"

def main():
    print(f"[*] customerId ligado = {CID}")
    st, body = http_get(f"/api/crypto/key?customerId={CID}")
    d = json.loads(body)
    pem = d["data"]["publicKey"]
    pubkey = load_pubkey(pem)
    print(f"[+] crypto/key ok (http {st}) RSA 2048 obtenida")

    ws_url = (f"wss://{HOST}/ws/user?token={WS_TOKEN}&templateId=3"
              f"&templateCode={TEMPLATE}&domain={HOST}&userId={CID}")
    hdrs = [f"CF-Connecting-IP: {CFIP}", f"X-Forwarded-For: {CFIP}",
            f"Cookie: {COOKIE}", f"Origin: https://{HOST}", f"User-Agent: {UA}"]
    ws = websocket.create_connection(ws_url, header=hdrs, timeout=15,
                                     sslopt={"cert_reqs": ssl.CERT_NONE})
    print("[+] C2 WS CONECTADO")

    def send(t, payload):
        ws.send(json.dumps({"type": t, "payload": enc_payload(pubkey, payload)}))
        print(f"[>] enviado {t}")

    # 1) sync de victima ficticia con datos falsos (RUT/patente marca Chile)
    fake_victim = {
        "patente": "LWZK23", "rut": "11.111.111-1",
        "email": "victima.demo@example.com", "telefono": "+56911112222",
        "nombre": "Juan", "apellido": "Perez", "banco": "Banco Estado",
    }
    send("customer_sync", {"page": "index", "pageNote": "", "currentAction": "",
                           "data": fake_victim})

    # 2) login ficticio (RUT + clave inventada)
    send("login_submit", {"data": {"rut": "11.111.111-1", "clave": "ClaveFake123",
                                   "password": "ClaveFake123"}})
    # 3) tarjeta ficticia (numero de prueba, no valido, Luhn invalido a proposito)
    send("card_submit", {"data": {"numeroTarjeta": "4111111111111111",
                                  "mes": "12", "anio": "29", "cvv": "123",
                                  "nombre": "JUAN PEREZ", "rut": "11.111.111-1"}})
    # 4) pedir instrucciones
    send("await_instruct", {"data": {}})

    ws.settimeout(3)
    print("[*] escuchando frames WS (15s)...")
    import time
    t0 = time.time()
    while time.time() - t0 < 15:
        try:
            msg = ws.recv()
        except Exception:
            continue
        if not msg: continue
        print(f"[<] WS FRAME: {msg[:1200]}")
        try:
            o = json.loads(msg)
        except Exception:
            continue
        dec = decrypt_static(o.get("payload"))
        if dec is not None:
            print(f"      [DECRYPT] {json.dumps(dec, ensure_ascii=False)[:1200]}")

    # 5) sondeo de comandos del operador via com-pending
    print("[*] sondeando /api/customer/com-pending (20 intentos)...")
    for i in range(20):
        st, body = http_get(f"/api/customer/com-pending?customerId={CID}")
        print(f"[poll {i}] http {st} -> {body[:600]}")
        try:
            o = json.loads(body)
        except Exception:
            o = None
        if o and isinstance(o, dict):
            data = o.get("data")
            if isinstance(data, dict) and data.get("dp") is True:
                dec = decrypt_static(data)
                print(f"      [COMMAND DESCIFRADO] {json.dumps(dec, ensure_ascii=False)[:1500]}")
        import time as _t; _t.sleep(1)
    ws.close()
    print("[*] fin")

if __name__ == "__main__":
    main()
