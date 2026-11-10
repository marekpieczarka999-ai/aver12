"""Aver Client - bot Discord + serwer licencji (jeden proces, hostowany 24/7).
Start: pip install -r requirements.txt ; skopiuj .env.example -> .env, uzupelnij ; python bot.py"""
import asyncio, base64, hashlib, json, os, re, secrets, sqlite3, time
from collections import defaultdict, deque
import aiohttp, discord
from aiohttp import web
from cryptography.hazmat.primitives import serialization
from discord import app_commands

def env_file():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(p):
        for l in open(p, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1); os.environ.setdefault(k.strip(), v.strip().strip('"'))
env_file()
TOKEN = os.getenv("DISCORD_TOKEN", "")
WEBHOOK = os.getenv("WEBHOOK_URL", "")
ADMINS = {int(x) for x in re.findall(r"\d+", os.getenv("ADMIN_IDS", ""))}
JB_ID, JB_KEY = os.getenv("JSONBIN_BIN_ID", ""), os.getenv("JSONBIN_KEY", "")
PORT = int(os.getenv("PORT", "8080"))
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"
BASE = os.path.dirname(os.path.abspath(__file__))
_pem = os.getenv("LICENSE_PRIVATE_KEY", "").replace("\\n", "\n").encode() or open(os.path.join(BASE, "license_private.pem"), "rb").read()   # na Renderze: klucz w zmiennej srodowiskowej, nie w repo
PRIV = serialization.load_pem_private_key(_pem, None)
BK_ID = os.getenv("JSONBIN_BACKUP_ID", "")   # osobny bin na kopie bazy (dysk Rendera free jest tymczasowy)
ACCENT, RED, GREEN, ORANGE = 0x6CB6FF, 0xE5484D, 0x3DD68C, 0xFFB224

# ---------------------------------------------------------------- baza
db = sqlite3.connect(os.getenv("DB_PATH") or os.path.join(BASE, "licenses.db"), check_same_thread=False)
db.row_factory = sqlite3.Row
db.execute("""CREATE TABLE IF NOT EXISTS keys(key TEXT PRIMARY KEY, type TEXT, hwid TEXT DEFAULT '', created INT, activated INT DEFAULT 0,
  expires INT DEFAULT 0, banned INT DEFAULT 0, reason TEXT DEFAULT '', note TEXT DEFAULT '', last_ip TEXT DEFAULT '', last_seen INT DEFAULT 0, last_name TEXT DEFAULT '')""")
db.commit()
def q(sql, *a): return db.execute(sql, a).fetchall()
def run(sql, *a): db.execute(sql, a); db.commit()
def get(key): r = q("SELECT * FROM keys WHERE key=?", key); return r[0] if r else None
def now(): return int(time.time() * 1000)

UNITS = {"m": 60_000, "h": 3_600_000, "d": 86_400_000, "w": 604_800_000}
LEGACY = {"1_day": "1d", "3_hours": "3h", "1_week": "1w", "1_month": "30d", "2_minutes": "2m", "developer_10s": "0m"}
def dur_ms(t):
    """None = nieprawidlowy format, 0 = lifetime."""
    t = LEGACY.get(t.lower().strip(), t.lower().strip())
    if t in ("lifetime", "life", "perm"): return 0
    m = re.fullmatch(r"(\d{1,4})([mhdw])", t)
    return int(m[1]) * UNITS[m[2]] if m else None
def new_key():
    a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "AVER-" + "-".join("".join(secrets.choice(a) for _ in range(4)) for _ in range(4))

# ---------------------------------------------------------------- token (Ed25519)
def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def make_token(key, hwid, typ, exp):
    p = b64(json.dumps({"k": key, "hw": hwid, "t": typ, "e": exp, "i": now()}, separators=(",", ":")).encode())
    return p + "." + b64(PRIV.sign(p.encode()))
def read_token(tok):
    try:
        p, s = tok.split(".", 1)
        PRIV.public_key().verify(unb64(s), p.encode())
        return json.loads(unb64(p))
    except Exception: return None

# ---------------------------------------------------------------- webhook (logi)
http = None
async def log(title, color, fields, desc=""):
    if not WEBHOOK or not http: return
    e = {"title": title, "color": color, "description": desc, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "fields": [{"name": n, "value": v or "-", "inline": i} for n, v, i in fields], "footer": {"text": "Aver Client • licencje"}}
    try: await http.post(WEBHOOK, json={"username": "Aver Licenses", "embeds": [e]}, timeout=aiohttp.ClientTimeout(total=10))
    except Exception as ex: print("webhook error:", ex)
def ts(ms, st="F"): return f"<t:{ms // 1000}:{st}>" if ms else "nigdy (lifetime)"
def tag(r): return "Lifetime" if not r["expires"] else r["type"]
async def log_login(ok, key, ip, hwid, name, r, why=""):
    f = [("🔑 Klucz", f"`{key}`", False), ("🌐 IP", f"`{ip}`", True), ("🕒 Data", ts(now()), True), ("👤 Nick", name or "-", True), ("💻 HWID", f"`{hwid[:12]}…`", True)]
    if r: f += [("📦 Typ", tag(r), True), ("⏳ Wygasa", ts(r["expires"], "R") if r["expires"] else "nigdy", True)]
    if ok: await log("✅ Logowanie", GREEN, f)
    else: await log("⛔ Nieudane logowanie", RED, f + [("Powód", why, False)])

# ---------------------------------------------------------------- API
hits = defaultdict(deque)
def client_ip(req):
    if TRUST_PROXY:
        h = req.headers.get("CF-Connecting-IP") or req.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if h: return h
    return req.remote or "?"
def limited(ip, n=20):
    d = hits[ip]; t = time.time()
    while d and t - d[0] > 60: d.popleft()
    d.append(t); return len(d) > n
def reply(**k): return web.json_response(k)

def verdict(r, hwid):
    """(kod, powod) albo None gdy klucz jest OK."""
    if r["banned"]: return "banned", r["reason"]
    if r["hwid"] and r["hwid"] != hwid: return "hwid", ""
    if r["activated"] and r["expires"] and now() >= r["expires"]: return "expired", ""
    return None

async def auth(req):
    ip = client_ip(req)
    if limited(ip): return web.json_response({"ok": False, "code": "rate"}, status=429)
    try: b = await req.json(); key = str(b["key"]).strip().upper(); hwid = str(b["hwid"])[:64]; name = str(b.get("name", ""))[:40]
    except Exception: return web.json_response({"ok": False, "code": "bad"}, status=400)
    r = get(key)
    if not r:
        await log_login(False, key, ip, hwid, name, None, "Nieprawidłowy klucz"); return reply(ok=False, code="invalid")
    if not r["hwid"] and not r["banned"]:   # pierwsza aktywacja: przypisz HWID i licz czas od teraz
        d = dur_ms(r["type"]) or 0; t = now()
        run("UPDATE keys SET hwid=?, activated=?, expires=? WHERE key=?", hwid, t, t + d if d else 0, key); r = get(key)
    v = verdict(r, hwid)
    if v:
        await log_login(False, key, ip, hwid, name, r, {"banned": "Klucz zbanowany: " + v[1], "hwid": "Inne urządzenie (HWID)", "expired": "Licencja wygasła"}[v[0]])
        return reply(ok=False, code=v[0], reason=v[1])
    run("UPDATE keys SET last_ip=?, last_seen=?, last_name=? WHERE key=?", ip, now(), name, key)
    await log_login(True, key, ip, hwid, name, r)
    return reply(ok=True, code="ok", token=make_token(key, hwid, r["type"], r["expires"]), type=r["type"], exp=r["expires"])

async def check(req):
    ip = client_ip(req)
    if limited(ip, 60): return web.json_response({"ok": False, "code": "rate"}, status=429)
    try: b = await req.json(); p = read_token(str(b["token"])); name = str(b.get("name", ""))[:40]
    except Exception: return web.json_response({"ok": False, "code": "bad"}, status=400)
    r = get(p["k"]) if p else None
    if not r: return reply(ok=False, code="invalid")
    v = verdict(r, p["hw"])
    if v: return reply(ok=False, code=v[0], reason=v[1])
    run("UPDATE keys SET last_seen=?, last_ip=?, last_name=? WHERE key=?", now(), ip, name or r["last_name"], p["k"])
    return reply(ok=True, code="ok", exp=r["expires"])

# ---------------------------------------------------------------- komendy Discord
def is_admin(i: discord.Interaction):
    return i.user.id in ADMINS if ADMINS else bool(i.guild and i.user.guild_permissions.administrator)
async def only_admin(i: discord.Interaction):
    if is_admin(i): return True
    await i.response.send_message("⛔ Brak uprawnień.", ephemeral=True); return False

def card(r):
    st = "🔴 zbanowany" if r["banned"] else ("🟡 nieaktywowany" if not r["activated"] else ("⚫ wygasł" if r["expires"] and now() >= r["expires"] else "🟢 aktywny"))
    e = discord.Embed(title=f"🔑 {r['key']}", color=RED if r["banned"] else ACCENT)
    e.add_field(name="Status", value=st); e.add_field(name="Typ", value=r["type"])
    e.add_field(name="Wygasa", value=ts(r["expires"], "R") if r["expires"] else ("po aktywacji" if not r["activated"] else "nigdy"))
    e.add_field(name="HWID", value=f"`{r['hwid'][:12]}…`" if r["hwid"] else "-"); e.add_field(name="Ostatnie IP", value=f"`{r['last_ip'] or '-'}`")
    e.add_field(name="Ostatnio", value=ts(r["last_seen"], "R") if r["last_seen"] else "-"); e.add_field(name="Nick", value=r["last_name"] or "-")
    if r["banned"]: e.add_field(name="Powód bana", value=r["reason"] or "-", inline=False)
    if r["note"]: e.add_field(name="Notatka", value=r["note"], inline=False)
    return e

async def health(req): return web.Response(text="ok")

# ---- kopia zapasowa kluczy w JSONBin (Render free kasuje dysk przy restarcie/deployu)
def _rows(): return [dict(r) for r in q("SELECT * FROM keys")]
async def backup_loop():
    last = None
    while BK_ID and JB_KEY:
        await asyncio.sleep(60)
        rows = _rows(); snap = json.dumps(rows, sort_keys=True)
        if snap == last: continue
        try:
            async with http.put(f"https://api.jsonbin.io/v3/b/{BK_ID}", json={"keys": rows}, headers={"X-Master-Key": JB_KEY}, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status == 200: last = snap
        except Exception as ex: print("backup error:", ex)
async def restore():
    if not (BK_ID and JB_KEY) or q("SELECT 1 FROM keys LIMIT 1"): return
    try:
        async with http.get(f"https://api.jsonbin.io/v3/b/{BK_ID}/latest", headers={"X-Master-Key": JB_KEY, "X-Bin-Meta": "false"}, timeout=aiohttp.ClientTimeout(total=20)) as r:
            for k in (await r.json()).get("keys", []):
                cols = list(k); db.execute(f"INSERT OR REPLACE INTO keys({','.join(cols)}) VALUES({','.join('?' * len(cols))})", [k[c] for c in cols])
            db.commit(); print("przywrocono klucze z kopii:", len(q("SELECT 1 FROM keys")))
    except Exception as ex: print("restore error:", ex)

class Bot(discord.Client):
    def __init__(s):
        super().__init__(intents=discord.Intents.default()); s.tree = app_commands.CommandTree(s)
    async def setup_hook(s): await s.tree.sync()
    async def on_ready(s): print(f"Bot zalogowany jako {s.user}", flush=True)
bot = Bot()
key = app_commands.Group(name="key", description="Zarządzanie kluczami licencyjnymi", default_permissions=discord.Permissions(administrator=True))
bot.tree.add_command(key)

async def need(i, k):
    r = get(k.strip().upper())
    if not r: await i.response.send_message("❌ Nie ma takiego klucza.", ephemeral=True)
    return r

@key.command(name="create", description="Generuje klucze (czas: 3h, 1d, 7d, 30d, 1w, lifetime)")
@app_commands.describe(duration="np. 1d, 7d, 30d, 12h, lifetime", count="ile kluczy (1-25)", note="notatka, np. nick kupującego")
async def k_create(i: discord.Interaction, duration: str, count: app_commands.Range[int, 1, 25] = 1, note: str = ""):
    if not await only_admin(i): return
    if dur_ms(duration) is None: return await i.response.send_message("❌ Zły czas. Przykłady: `3h`, `1d`, `7d`, `30d`, `lifetime`.", ephemeral=True)
    ks = []
    for _ in range(count):
        k = new_key(); run("INSERT INTO keys(key,type,created,note) VALUES(?,?,?,?)", k, duration.lower(), now(), note[:100]); ks.append(k)
    await i.response.send_message(embed=discord.Embed(title=f"✅ Utworzono {count} × {duration}", description="\n".join(f"`{k}`" for k in ks), color=GREEN), ephemeral=True)
    await log("🆕 Nowe klucze", ACCENT, [("Typ", duration, True), ("Ilość", str(count), True), ("Admin", i.user.mention, True)])

@key.command(name="ban", description="Banuje klucz (gracz zostanie wyrzucony z gry w ~30 s)")
async def k_ban(i: discord.Interaction, klucz: str, powod: str = ""):
    if not await only_admin(i) or not (r := await need(i, klucz)): return
    run("UPDATE keys SET banned=1, reason=? WHERE key=?", powod[:150], r["key"])
    await i.response.send_message(f"🔨 Zbanowano `{r['key']}`.", ephemeral=True)
    await log("🔨 Klucz zbanowany", RED, [("🔑 Klucz", f"`{r['key']}`", False), ("Powód", powod or "-", True), ("Admin", i.user.mention, True), ("🕒 Data", ts(now()), True)])

@key.command(name="unban", description="Odbanowuje klucz")
async def k_unban(i: discord.Interaction, klucz: str):
    if not await only_admin(i) or not (r := await need(i, klucz)): return
    run("UPDATE keys SET banned=0, reason='' WHERE key=?", r["key"])
    await i.response.send_message(f"✅ Odbanowano `{r['key']}`.", ephemeral=True)
    await log("♻️ Klucz odbanowany", GREEN, [("🔑 Klucz", f"`{r['key']}`", False), ("Admin", i.user.mention, True)])

@key.command(name="info", description="Informacje o kluczu")
async def k_info(i: discord.Interaction, klucz: str):
    if not await only_admin(i) or not (r := await need(i, klucz)): return
    await i.response.send_message(embed=card(r), ephemeral=True)

@key.command(name="extend", description="Przedłuża klucz (np. 7d, 30d, 12h)")
async def k_extend(i: discord.Interaction, klucz: str, czas: str):
    if not await only_admin(i) or not (r := await need(i, klucz)): return
    d = dur_ms(czas)
    if not d: return await i.response.send_message("❌ Zły czas (np. `7d`).", ephemeral=True)
    if not r["activated"]: return await i.response.send_message("ℹ️ Klucz jeszcze nieaktywowany - czas liczy się od pierwszego logowania. Zmień typ: utwórz nowy klucz.", ephemeral=True)
    if not r["expires"]: return await i.response.send_message("ℹ️ To klucz lifetime.", ephemeral=True)
    run("UPDATE keys SET expires=? WHERE key=?", max(r["expires"], now()) + d, r["key"])
    await i.response.send_message(embed=card(get(r["key"])), ephemeral=True)

@key.command(name="resethwid", description="Zdejmuje przypisanie do komputera (gracz zmienił PC)")
async def k_reset(i: discord.Interaction, klucz: str):
    if not await only_admin(i) or not (r := await need(i, klucz)): return
    run("UPDATE keys SET hwid='' WHERE key=?", r["key"])
    await i.response.send_message(f"💻 Zresetowano HWID `{r['key']}`.", ephemeral=True)
    await log("💻 Reset HWID", ORANGE, [("🔑 Klucz", f"`{r['key']}`", False), ("Admin", i.user.mention, True)])

@key.command(name="delete", description="Usuwa klucz na stałe")
async def k_del(i: discord.Interaction, klucz: str):
    if not await only_admin(i) or not (r := await need(i, klucz)): return
    run("DELETE FROM keys WHERE key=?", r["key"])
    await i.response.send_message(f"🗑️ Usunięto `{r['key']}`.", ephemeral=True)

@key.command(name="list", description="Lista ostatnich 20 kluczy")
async def k_list(i: discord.Interaction, tylko_zbanowane: bool = False):
    if not await only_admin(i): return
    rs = q("SELECT * FROM keys " + ("WHERE banned=1 " if tylko_zbanowane else "") + "ORDER BY created DESC LIMIT 20")
    ic = lambda r: "🔴" if r["banned"] else ("🟡" if not r["activated"] else ("⚫" if r["expires"] and now() >= r["expires"] else "🟢"))
    await i.response.send_message(embed=discord.Embed(title="🔑 Klucze", description="\n".join(f"{ic(r)} `{r['key']}` · {r['type']} · {r['last_name'] or '-'}" for r in rs) or "Brak.", color=ACCENT), ephemeral=True)


def iso_ms(t):
    import datetime as dt
    try:
        d = dt.datetime.fromisoformat(str(t).replace("Z", "+00:00"))
        return int((d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)).timestamp() * 1000)
    except Exception: return 0

@key.command(name="import", description="Importuje klucze ze starego JSONBin (te, których bot jeszcze nie zna)")
async def k_import(i: discord.Interaction):
    if not await only_admin(i): return
    if not JB_ID: return await i.response.send_message("❌ Ustaw JSONBIN_BIN_ID i JSONBIN_KEY w .env.", ephemeral=True)
    await i.response.defer(ephemeral=True)
    try:
        async with http.get(f"https://api.jsonbin.io/v3/b/{JB_ID}/latest", headers={"X-Master-Key": JB_KEY, "X-Bin-Meta": "false"}, timeout=aiohttp.ClientTimeout(total=20)) as r:
            data = await r.json(content_type=None)
            if r.status != 200: return await i.followup.send(f"❌ JSONBin: HTTP {r.status}", ephemeral=True)
        n = 0
        for e in (data.get("record", data).get("keys") or []):
            k = str(e.get("key", "")).strip().upper()
            if not k or get(k): continue
            off = e.get("active") is False
            run("INSERT INTO keys(key,type,hwid,created,activated,expires,banned,reason) VALUES(?,?,?,?,?,?,?,?)", k, LEGACY.get(str(e.get("type", "lifetime")), str(e.get("type", "lifetime"))),
                str(e.get("hwid") or ""), now(), iso_ms(e.get("activated_at")), iso_ms(e.get("expires_at")), 1 if (e.get("banned") or off) else 0, str(e.get("ban_reason") or ("dezaktywowany" if off else ""))[:150]); n += 1
        await i.followup.send(f"✅ Zaimportowano {n} kluczy.", ephemeral=True)
    except Exception as ex: await i.followup.send(f"❌ Błąd importu: {ex}", ephemeral=True)

async def main():
    global http
    discord.utils.setup_logging()
    http = aiohttp.ClientSession()
    await restore()                                   # najpierw baza, potem API (inaczej klienci dostaliby "invalid")
    app = web.Application(); app.add_routes([web.post("/api/auth", auth), web.post("/api/check", check), web.get("/", health)])
    rn = web.AppRunner(app); await rn.setup(); await web.TCPSite(rn, "0.0.0.0", PORT).start()
    print(f"API licencji: port {PORT}", flush=True)
    asyncio.create_task(backup_loop())
    try: await bot.start(TOKEN)
    except discord.HTTPException as e:
        if e.status != 429: raise
        print("Discord 429 (limit IP hostingu) - ponowna proba za 15 min; API licencji dziala dalej", flush=True)
        await asyncio.sleep(900)
        import sys; os.execv(sys.executable, [sys.executable] + sys.argv)

if __name__ == "__main__":
    if not TOKEN: raise SystemExit("Brak DISCORD_TOKEN w .env")
    asyncio.run(main())
