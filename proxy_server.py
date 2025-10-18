import asyncio
import struct
import socket
import sys
import logging
import os
import sqlite3
import hashlib
import hmac
import binascii
import html
from urllib.parse import parse_qs, urlparse

# ---- CONFIG ----
SOCKS_PORT = 6767
HTTP_PORT = 80
DB_PATH = "proxy_users.db"
ADMIN_USER = "admin"
ADMIN_PASS = "your_password"  # <= mot de passe que tu as fourni
ALLOWED_PREFIXES = ("26.", "147.", "185.")  # conserve si tu veux filtrer destinations

# PBKDF2 params
PBKDF2_ITERS = 150_000
SALT_BYTES = 16
HASH_NAME = "sha256"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ----------------- DB helpers -----------------
def init_db(path=DB_PATH):
    conn = sqlite3.connect(path, check_same_thread=False)
    cur = conn.cursor()
    cur.execute(
        """CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            pw_hash TEXT NOT NULL
        )"""
    )
    conn.commit()
    return conn


def hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac(HASH_NAME, password.encode("utf-8"), salt, PBKDF2_ITERS)
    return binascii.hexlify(dk).decode()


def add_user(conn, username: str, password: str) -> bool:
    username = username.strip()
    if not username:
        return False
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
    if cur.fetchone():
        return False
    salt = os.urandom(SALT_BYTES)
    pw_hash = hash_password(password, salt)
    cur.execute("INSERT INTO users(username, salt, pw_hash) VALUES (?, ?, ?)",
                (username, binascii.hexlify(salt).decode(), pw_hash))
    conn.commit()
    return True


def del_user(conn, username: str) -> bool:
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=?", (username,))
    changed = cur.rowcount
    conn.commit()
    return changed > 0


def list_users(conn):
    cur = conn.cursor()
    cur.execute("SELECT username FROM users ORDER BY username")
    return [r[0] for r in cur.fetchall()]


def verify_user(conn, username: str, password: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT salt, pw_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    if not row:
        return False
    salt_hex, pw_hash_db = row
    salt = binascii.unhexlify(salt_hex)
    pw_hash = hash_password(password, salt)
    return hmac.compare_digest(pw_hash, pw_hash_db)


# ----------------- Admin panel (noice) -----------------
def parse_basic_auth(headers):
    auth = headers.get("authorization")
    if not auth:
        return None, None
    try:
        typ, data = auth.split(" ", 1)
        if typ.lower() != "basic":
            return None, None
        import base64
        decoded = base64.b64decode(data).decode(errors="ignore")
        user, pwd = decoded.split(":", 1)
        return user, pwd
    except Exception:
        return None, None


def http_response(status_code=200, body="", headers=None):
    reason = {200: "OK", 201: "Created", 302: "Found", 400: "Bad Request", 401: "Unauthorized",
              403: "Forbidden", 404: "Not Found", 500: "Internal Server Error"}.get(status_code, "OK")
    h = {"Content-Type": "text/html; charset=utf-8", "Content-Length": str(len(body.encode("utf-8")))}
    if headers:
        h.update(headers)
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in h.items())
    return f"HTTP/1.1 {status_code} {reason}\r\n{header_lines}\r\n{body}".encode("utf-8")


# HTML + CSS + minimal JS
ADMIN_HTML_TEMPLATE = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proxy Admin</title>
<style>
:root{{--bg:#0f1720;--card:#0b1220;--muted:#9aa5b1;--accent:#3b82f6;--danger:#ef4444;--success:#10b981;--text:#e6eef6}}
html,body{{height:100%;margin:0;font-family:Inter,Segoe UI,Arial;background:linear-gradient(180deg,#071028, #07182a);color:var(--text);}}
.container{{max-width:900px;margin:32px auto;padding:20px;}}
.header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}}
.card{{background:rgba(255,255,255,0.03);border-radius:10px;padding:18px;box-shadow:0 6px 18px rgba(2,6,23,0.6)}}
.h1{{font-size:20px;margin:0}}
.list{{margin:12px 0;padding:0;list-style:none}}
.list li{{display:flex;justify-content:space-between;align-items:center;padding:8px 10px;border-radius:8px;background:rgba(255,255,255,0.01);margin-bottom:8px}}
.input-row{{display:flex;gap:8px}}
input[type=text],input[type=password]{{flex:1;padding:8px;border-radius:8px;border:1px solid rgba(255,255,255,0.04);background:transparent;color:var(--text)}}
button{{padding:8px 12px;border-radius:8px;border:0;background:var(--accent);color:white;cursor:pointer}}
.btn-danger{{background:var(--danger)}}
.small{{font-size:13px;color:var(--muted)}}
.msg{{padding:8px;border-radius:8px;margin-bottom:10px}}
.success{{background:rgba(16,185,129,0.12);border:1px solid rgba(16,185,129,0.18)}}
.error{{background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.12)}}
.footer{{margin-top:18px;font-size:13px;color:var(--muted)}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="h1">Tempox Proxy Admin</div>
      <div class="small">Tous les utilisateurs SOCKS5</div>
    </div>
    <div class="small"><strong>Bienvenue, Admin !</strong></div>
  </div>

  <div class="card" id="mainCard">
    <div id="msg"></div>

    <h3>Utilisateurs</h3>
    <ul id="users" class="list"></ul>

    <h3>Créer un utilisateur</h3>
    <div class="input-row" style="margin-bottom:10px">
      <input id="new_user" type="text" placeholder="Nom d'utilisateur"/>
      <input id="new_pass" type="password" placeholder="Mot de passe"/>
      <button id="createBtn">Créer</button>
    </div>
    <div class="small">Remarque : les mots de passe sont hachés côté serveur (PBKDF2).</div>
    <div class="footer">© Tempox Interactive Group</div>
  </div>
</div>

<script>
const authHeader = 'Basic ' + btoa('{admin_user}:{admin_pass}');
async function loadUsers(){{
  const r = await fetch('/list', {{headers:{{'Authorization': authHeader}}}});
  if(!r.ok){{document.getElementById('mainCard').innerHTML='<p class="error">Auth requise</p>';return;}}
  const j = await r.json();
  renderUsers(j.users);
}}
function renderUsers(users){{
  const ul=document.getElementById('users');ul.innerHTML='';
  users.forEach(u=>{{
    const li=document.createElement('li');
    const span=document.createElement('span');span.textContent=u;
    const del=document.createElement('button');del.textContent='Supprimer';del.className='btn-danger';
    del.onclick=async()=>{{
      if(!confirm('Supprimer '+u+' ?'))return;
      const r=await fetch('/delete?user='+encodeURIComponent(u),{{headers:{{'Authorization':authHeader}}}});
      if(r.ok){{showMsg('Supprimé','success');loadUsers();}}else{{showMsg('Erreur suppression','error');}}
    }};
    li.appendChild(span);li.appendChild(del);ul.appendChild(li);
  }});
}}
function showMsg(t,c){{const d=document.getElementById('msg');d.innerHTML='<div class="msg '+(c==='success'?'success':'error')+'">'+t+'</div>';setTimeout(()=>d.innerHTML='',4000);}}
document.getElementById('createBtn').onclick=async()=>{{
  const u=document.getElementById('new_user').value.trim();
  const p=document.getElementById('new_pass').value;
  if(!u||!p){{showMsg('Username et password requis','error');return;}}
  const body=new URLSearchParams();body.append('username',u);body.append('password',p);
  const r=await fetch('/add',{{method:'POST',headers:{{'Authorization':authHeader,'Content-Type':'application/x-www-form-urlencoded'}},body:body.toString()}});
  if(r.ok){{showMsg('Créé','success');document.getElementById('new_user').value='';document.getElementById('new_pass').value='';loadUsers();}}
  else{{showMsg('Erreur création','error');}}
}}
window.addEventListener('load',loadUsers);
</script>
</body>
</html>
"""


async def handle_admin_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, conn):
    peer = writer.get_extra_info("peername")
    logging.info("Admin HTTP connexion depuis %s", peer)
    try:
        raw = b""
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
        except Exception:
            raw = await reader.read(4096)
        header_text = raw.decode(errors="ignore")
        lines = header_text.split("\r\n")
        request_line = lines[0] if lines else ""
        method, path, _ = request_line.split(" ", 2) if request_line else ("GET", "/", "HTTP/1.1")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        # check Basic Auth
        user, pwd = parse_basic_auth({k: v for k, v in headers.items()})
        if user != ADMIN_USER or pwd != ADMIN_PASS:
            body = "<h3>Authentication required</h3>"
            resp = http_response(401, body, headers={"WWW-Authenticate": 'Basic realm="admin"'})
            writer.write(resp)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        parsed = urlparse(path)
        qs = parse_qs(parsed.query)

        # API endpoints for JS
        if method == "GET" and parsed.path == "/list":
            users = list_users(conn)
            body = '{"users":' + str(users).replace("'", '"') + "}"
            writer.write(http_response(200, body, headers={"Content-Type": "application/json; charset=utf-8"}))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        if method == "GET" and parsed.path == "/delete":
            username = qs.get("user", [""])[0]
            if username:
                del_user(conn, username)
            writer.write(http_response(200, "<p>deleted</p>"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        if method == "POST" and parsed.path == "/add":
            content_length = int(headers.get("content-length", "0"))
            body_bytes = b""
            if content_length > 0:
                body_bytes = await reader.readexactly(content_length)
            form = parse_qs(body_bytes.decode())
            username = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
            ok = False
            if username and password:
                ok = add_user(conn, username, password)
            if ok:
                writer.write(http_response(201, "<p>created</p>"))
            else:
                writer.write(http_response(400, "<p>error (exists or invalid)</p>"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        # default: return admin panel HTML for GET /
        if method == "GET" and (parsed.path == "/" or parsed.path == "/index"):
            page = ADMIN_HTML_TEMPLATE.format(admin_user=html.escape(ADMIN_USER), admin_pass=html.escape(ADMIN_PASS))
            writer.write(http_response(200, page))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        # fallback 404
        writer.write(http_response(404, "<h3>Not found</h3>"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    except Exception as exc:
        logging.exception("Admin handler error: %s", exc)
        try:
            writer.write(http_response(500, "<h3>Server Error</h3>"))
            await writer.drain()
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ------------- SOCKS5 handler (username/password) -------------
SOCKS5_VERSION = 0x05

async def handle_socks5(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, conn):
    peer = writer.get_extra_info("peername")
    logging.info("SOCKS connection from %s", peer)
    try:
        # handshake
        header = await reader.readexactly(2)
        ver, nmethods = header[0], header[1]
        if ver != SOCKS5_VERSION:
            writer.close()
            return
        methods = await reader.readexactly(nmethods)
        # prefer username/password (0x02)
        if 0x02 in methods:
            writer.write(bytes([SOCKS5_VERSION, 0x02]))
            await writer.drain()
            # read auth request (RFC1929)
            auth_hdr = await reader.readexactly(2)
            auth_ver, ulen = auth_hdr[0], auth_hdr[1]
            if auth_ver != 0x01:
                writer.write(b"\x01\x01")
                await writer.drain()
                writer.close()
                return
            uname = (await reader.readexactly(ulen)).decode(errors="ignore")
            plen_b = await reader.readexactly(1)
            plen = plen_b[0]
            passwd = (await reader.readexactly(plen)).decode(errors="ignore")
            if verify_user(conn, uname, passwd):
                writer.write(b"\x01\x00")
                await writer.drain()
            else:
                writer.write(b"\x01\x01")
                await writer.drain()
                writer.close()
                return
        else:
            writer.write(bytes([SOCKS5_VERSION, 0xFF]))
            await writer.drain()
            writer.close()
            return

        # request
        req_header = await reader.readexactly(4)
        ver, cmd, _, atyp = req_header
        if ver != SOCKS5_VERSION or cmd != 0x01:
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return

        if atyp == 0x01:
            addr_bytes = await reader.readexactly(4)
            dest_addr = socket.inet_ntoa(addr_bytes)
        elif atyp == 0x03:
            domain_len = (await reader.readexactly(1))[0]
            dest_addr = (await reader.readexactly(domain_len)).decode()
        elif atyp == 0x04:
            addr_bytes = await reader.readexactly(16)
            try:
                dest_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            except Exception:
                dest_addr = None
        else:
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return

        dest_port = struct.unpack("!H", await reader.readexactly(2))[0]
        logging.info("User requested CONNECT %s:%s", dest_addr, dest_port)

        # optional IP filter
        allow = True
        if ALLOWED_PREFIXES:
            allow = False
            if dest_addr and dest_addr.replace(".", "").isdigit():
                for p in ALLOWED_PREFIXES:
                    if dest_addr.startswith(p):
                        allow = True
                        break
            else:
                try:
                    resolved = socket.gethostbyname(dest_addr)
                    for p in ALLOWED_PREFIXES:
                        if resolved.startswith(p):
                            allow = True
                            break
                except Exception:
                    allow = False

        if not allow:
            logging.warning("Rejected by IP rule: %s:%s", dest_addr, dest_port)
            writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return

        # connect to destination
        try:
            remote_reader, remote_writer = await asyncio.open_connection(dest_addr, dest_port)
        except Exception as e:
            logging.warning("Failed to connect to dest: %s", e)
            writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return

        # reply success
        sock = remote_writer.get_extra_info("socket")
        if sock:
            try:
                local_ip, local_port = sock.getsockname()[:2]
                bnd_addr = socket.inet_aton(local_ip)
            except Exception:
                bnd_addr = b"\x00\x00\x00\x00"
                local_port = 0
        else:
            bnd_addr = b"\x00\x00\x00\x00"
            local_port = 0

        writer.write(b"\x05\x00\x00\x01" + bnd_addr + struct.pack("!H", local_port))
        await writer.drain()

        # relay
        async def relay(r, w):
            try:
                while True:
                    data = await r.read(4096)
                    if not data:
                        break
                    w.write(data)
                    await w.drain()
            except Exception:
                pass
            finally:
                try:
                    w.close()
                except Exception:
                    pass

        t1 = asyncio.create_task(relay(reader, remote_writer))
        t2 = asyncio.create_task(relay(remote_reader, writer))
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)

        try:
            remote_writer.close()
            await remote_writer.wait_closed()
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    except asyncio.IncompleteReadError:
        pass
    except Exception as exc:
        logging.exception("SOCKS handler error: %s", exc)
        try:
            writer.close()
        except Exception:
            pass


# ----------------- Main -----------------
async def main():
    conn = init_db(DB_PATH)

    # servers
    async def http_factory(reader, writer):
        await handle_admin_http(reader, writer, conn)

    http_server = await asyncio.start_server(http_factory, "0.0.0.0", HTTP_PORT)

    async def socks_factory(reader, writer):
        await handle_socks5(reader, writer, conn)

    socks_server = await asyncio.start_server(socks_factory, "0.0.0.0", SOCKS_PORT)

    logging.info("Admin HTTP listening on %s", ", ".join(str(s.getsockname()) for s in http_server.sockets))
    logging.info("SOCKS5 listening on %s", ", ".join(str(s.getsockname()) for s in socks_server.sockets))

    async with http_server, socks_server:
        await asyncio.gather(http_server.serve_forever(), socks_server.serve_forever())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except PermissionError:
        logging.error("PermissionError: cannot bind port (maybe used or blocked).")
    except KeyboardInterrupt:
        logging.info("Stopped by user.")
