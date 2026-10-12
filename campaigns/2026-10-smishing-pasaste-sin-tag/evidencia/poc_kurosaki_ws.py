#!/usr/bin/env python3
# PoC: handshake al canal C2 /ws/user enviando la cabecera de bypass de cloaking.
import ssl, json, sys
import websocket

TOKEN = "eSDJOKGskskaklHUGF45IOJIOSAsjjkjnklgSIGhjksdIHIOGFA23SDKKsdhjg"
URL = (f"wss://peasastesintag.sbs/ws/user?token={TOKEN}"
       "&templateId=3&templateCode=JIEYOUTEMPLATE-20260906182151-4A0T"
       "&domain=peasastesintag.sbs&userId=u_q9v2ie6z49nmv5fylqh")
COOKIE = "_entry_session=JIEYOUTEMPLATE-20260906182151-4A0T%3A1791820844.5aff086c67918b7da8bd9435610b82db"

def attempt(label, headers, subprotocols=None):
    print(f"===== {label} =====")
    try:
        ws = websocket.create_connection(
            URL, header=headers, timeout=15,
            sslopt={"cert_reqs": ssl.CERT_NONE},
            subprotocols=subprotocols,
        )
        print("[+] CONNECTED. subprotocol:", ws.getsubprotocol())
        ws.settimeout(8)
        for i in range(5):
            try:
                msg = ws.recv()
                print(f"[RECV {i}] {msg[:1500]}")
            except Exception as e:
                print(f"[recv stop] {e}")
                break
        ws.close()
    except websocket.WebSocketBadStatusException as e:
        print(f"[HTTP STATUS] {e.status}")
        print("[RESP HEADERS]")
        try:
            for k, v in e.headers.items():
                print(f"   {k}: {v}")
        except Exception:
            print("   <no headers>", e)
    except Exception as e:
        print(f"[ERR] {type(e).__name__}: {e}")

base = [
    "CF-Connecting-IP: 190.44.5.5",
    "X-Forwarded-For: 190.44.5.5",
    "X-Real-IP: 190.44.5.5",
    "Origin: https://peasastesintag.sbs",
    "User-Agent: Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36",
]

attempt("1) CF header only", base)
attempt("2) CF header + cookie", base + [f"Cookie: {COOKIE}"])
attempt("3) CF + cookie + subprotocol", base + [f"Cookie: {COOKIE}"], subprotocols=["binary"])
