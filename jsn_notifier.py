#!/usr/bin/env python3
"""JSN WiFi - বিল নোটিশ পপ-আপ সিস্টেম (MikroTik PPPoE ইউজারদের জন্য)

  python jsn_notifier.py report [YYYY-MM-DD]   # রাউটার ছাড়াই দেখুন কে কোন অবস্থায়
  python jsn_notifier.py serve                 # সার্ভার + MikroTik সিঙ্ক চালু
"""
import hashlib, ipaddress, re, secrets, socket, urllib.request, base64, html as _html, calendar, configparser, csv, datetime as dt, glob, hmac, io, json, shutil, sys, threading, time
from urllib.parse import urlparse, parse_qs
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
cfg = configparser.ConfigParser()
cfg.read(BASE / "config.ini", encoding="utf-8")
C, R, P = cfg["billing"], cfg["router"], cfg["portal"]
A = cfg["admin"]
ADMIN_HOSTS = {h.strip() for h in A.get("hosts", "localhost,127.0.0.1").split(",")}
DATA_DIR = BASE / "data"
SYNC, ACTIVE = {"ok": False, "time": "", "msg": "এখনো সিঙ্ক হয়নি"}, {}
WARN_DAYS = int(C.get("warn_days_before", 3))
TEMPLATE = (BASE / "popup.html").read_text(encoding="utf-8")
STATE, LOCK = {}, threading.Lock()          # ip -> info
BN = str.maketrans("0123456789", "০১২৩৪৫৬৭৮৯")
MONTHS = "জানুয়ারি ফেব্রুয়ারি মার্চ এপ্রিল মে জুন জুলাই আগস্ট সেপ্টেম্বর অক্টোবর নভেম্বর ডিসেম্বর".split()


def bn(x): return str(x).translate(BN)
def bn_date(d): return f"{bn(d.day)} {MONTHS[d.month-1]} {bn(d.year)}"


def add_month(d):
    y, m = d.year + (d.month == 12), d.month % 12 + 1
    return dt.date(y, m, min(d.day, calendar.monthrange(y, m)[1]))


def load_full():
    """ইউজার -> সর্বশেষ পেমেন্ট, প্যাকেজ, পরের মেয়াদ (একই তারিখ, পরের মাস)"""
    last = {}
    for f in sorted(glob.glob(str(BASE / C.get("csv_glob", "data/*.csv")))):
        for row in csv.DictReader(open(f, encoding="utf-8-sig")):
            if not (row.get("Date") or "").strip():
                continue
            d = dt.datetime.strptime(row["Date"].strip(), "%d-%b-%Y %I:%M:%S %p").date()
            u = row["User"].strip()
            if u not in last or d >= last[u]["last"]:
                last[u] = dict(last=d, pkg=(row.get("Package") or "").strip())
    for v in last.values():
        v["exp"] = add_month(v["last"])
    return last


def load_expiry():
    return {u: v["exp"] for u, v in load_full().items()}


def classify(exp, today):
    left = (exp - today).days
    if left <= 0: return "expired", left
    if left <= warn_days(): return "warn", left
    return "ok", left


def report(today):
    out = {"warn": [], "expired": [], "ok": []}
    for u, e in sorted(load_expiry().items(), key=lambda x: x[1]):
        s, left = classify(e, today)
        out[s].append((u, e, left))
    print(f"তারিখ: {today}  | warn={len(out['warn'])} expired={len(out['expired'])} ok={len(out['ok'])}")
    for s in ("warn", "expired"):
        for u, e, left in out[s]:
            print(f"  [{s:7}] {u:28} মেয়াদ {e}  ({left} দিন)")


# ---------- MikroTik ----------
SETTINGS = BASE / "settings.json"          # ড্যাশবোর্ড থেকে সেভ করা রাউটার সেটিং (config.ini এর উপরে)
MANUAL, ACTIVE_LIST, SYNC_LOCK = {}, [], threading.Lock()


def rs():
    d = dict(R)
    if SETTINGS.exists():
        d.update(json.loads(SETTINGS.read_text(encoding="utf-8")))
    return d


def router():
    from librouteros import connect
    c = rs()
    kw = dict(host=c["host"], username=c["user"], password=c["password"], port=int(c.get("port", 8728)), timeout=8)
    if str(c.get("ssl", "")).lower() in ("1", "true", "yes"):
        import ssl
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try: ctx.set_ciphers("ADH:@SECLEVEL=0")
        except Exception: pass
        kw["ssl_wrapper"] = ctx.wrap_socket
    return connect(**kw)


def sync_once():
    with SYNC_LOCK:
        today = dt.date.today()
        api = router()
        try:
            rows = [r for r in api.path("ppp", "active") if "address" in r]
            active = {r["name"]: r["address"] for r in rows}
            want, state = set(), {}
            for u, e in load_expiry().items():
                ip = active.get(u)
                s, left = classify(e, today)
                if ip and s != "ok":
                    want.add(("bill-warn" if s == "warn" else "bill-expired", ip))
                    state[ip] = dict(user=u, status=s, left=left, exp=e)
            al = api.path("ip", "firewall", "address-list")
            have, other = {}, set()
            for r in al:
                c = r.get("comment") or ""
                if c == "jsn-auto": have[(r["list"], r["address"])] = r[".id"]
                elif c.startswith("jsn-"): other.add((r["list"], r["address"]))
            for k, i in have.items():
                if k not in want: al.remove(i)
            for lst, ip in want - set(have) - other:
                try: al.add(**{"list": lst, "address": ip, "comment": "jsn-auto"})
                except Exception as ex: print("add skip:", ex)
        finally:
            api.close()
        now = time.time()
        with LOCK:
            for ip, m in list(MANUAL.items()):
                if m["until"] < now: del MANUAL[ip]
                else: state.setdefault(ip, dict(user=m["user"], status="manual", left=None, exp=m.get("exp"), msg=m.get("msg", "")))
            STATE.clear(); STATE.update(state)
            ACTIVE.clear(); ACTIVE.update(active)
            ACTIVE_LIST[:] = [dict(name=r["name"], address=r["address"], uptime=r.get("uptime", ""), mac=r.get("caller-id", ""), service=r.get("service", "")) for r in rows]
            SYNC.update(ok=True, time=time.strftime("%H:%M:%S"), msg=f"রাউটার সংযুক্ত · অনলাইন PPPoE: {len(active)}")
        print(time.strftime("%H:%M:%S"), f"sync ok: warn={sum(v['status']=='warn' for v in state.values())} expired={sum(v['status']=='expired' for v in state.values())}")


def sync_loop():
    while True:
        try: sync_once()
        except Exception as ex:
            print("sync error:", ex)
            SYNC.update(ok=False, time=time.strftime("%H:%M:%S"), msg=f"রাউটার সংযোগ ব্যর্থ: {ex}")
        time.sleep(int(ui()["sync_seconds"]))


def ack(ip):
    api = router()
    try: api.path("ip", "firewall", "address-list").add(list="bill-seen", address=ip, timeout=ui()["seen_timeout"], comment="jsn-ack")
    finally: api.close()


def push(user, msg="", minutes=30):
    """অনলাইন ইউজারকে তাৎক্ষণিক সতর্কবার্তা পপ-আপ পাঠান"""
    ip = ACTIVE.get(user)
    if not ip: raise ValueError("ইউজার এখন অনলাইনে নেই")
    api = router()
    try:
        al = api.path("ip", "firewall", "address-list")
        for r in list(al):
            if r.get("list") == "bill-seen" and r.get("address") == ip: al.remove(r[".id"])
        try: al.add(list="bill-warn", address=ip, timeout=f"{int(minutes)}m", comment="jsn-manual")
        except Exception as ex: print("push add skip:", ex)
    finally:
        api.close()
    e = load_expiry().get(user)
    with LOCK:
        MANUAL[ip] = dict(user=user, until=time.time() + int(minutes) * 60, msg=msg.strip()[:300], exp=e)
        STATE[ip] = STATE.get(ip) or dict(user=user, status="manual", left=None, exp=e, msg=msg.strip()[:300])


# ---------- সেটিং (settings.json) ----------
SET_LOCK, _CACHE = threading.RLock(), [0, {}]
DEF_UI = dict(title="বিল নোটিশ ড্যাশবোর্ড", sub="Furqan Cloud · JSN WiFi", brand="Furqan Cloud", logo="F", acc="",
              warn_days=3, sync_seconds=60, refresh=15, seen_timeout="3h", push_minutes=30, session_hours=12)
ASSETS = json.loads((BASE / "popup_assets.json").read_text())
DEF_POPUP = dict(numbers=[dict(label="Send Money", number="01670-209041", brand="bKash"), dict(label="Cash Out", number="01815-220716", brand="bKash")],
                 office="যশোদল গোসাই বাজার, কিশোরগঞ্জ", phone="01775203815", logo="",
                 warn_notice="সংযোগ বন্ধ হওয়া এড়াতে মেয়াদ শেষ হওয়ার আগেই বিল পরিশোধ করুন।",
                 expired_notice="সংযোগ পুনরায় চালু করতে অনুগ্রহ করে আপনার বকেয়া বিল পরিশোধ করুন। পেমেন্ট নিশ্চিত হলে সংযোগ চালু করা হবে।")
DEF_ACCESS = dict(domain="", public_ip="", pc_ip="")


def cfg_all():
    with SET_LOCK:
        try: m = SETTINGS.stat().st_mtime
        except OSError: return {}
        if m != _CACHE[0]:
            _CACHE[:] = [m, json.loads(SETTINGS.read_text(encoding="utf-8"))]
        return _CACHE[1]


def cfg_section(name, default):
    d = dict(default); d.update(cfg_all().get(name, {})); return d


def cfg_save(name, val):
    with SET_LOCK:
        s = dict(cfg_all()); s[name] = val
        SETTINGS.write_text(json.dumps(s, ensure_ascii=False), encoding="utf-8"); _CACHE[0] = 0


def ui():
    u = cfg_section("ui", DEF_UI)
    if "ui" not in cfg_all(): u["warn_days"] = WARN_DAYS
    return u


def warn_days(): return int(ui()["warn_days"])
def ui_public():
    u = ui(); return {k: u[k] for k in ("title", "sub", "brand", "logo", "refresh", "push_minutes")}


def theme_css():
    a = ui()["acc"]
    if not a: return ""
    return f"<style>:root{{--purple:{a}!important;--purple-d:color-mix(in srgb,{a},#000 30%)!important}}</style>"


HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
HOST = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
TMO = re.compile(r"^\d{1,4}[smhd]$")
PHONE = re.compile(r"^[0-9+\- ]{5,20}$")


def clean(s, n=200): return str(s if s is not None else "").strip()[:n]
def ip4(s):
    if s == "": return s
    ipaddress.IPv4Address(s); return s
def num(v, lo, hi, name):
    try: n = int(str(v).strip())
    except ValueError: raise ValueError(f"{name}: সংখ্যা দিন")
    if not lo <= n <= hi: raise ValueError(f"{name}: {lo} থেকে {hi} এর মধ্যে হতে হবে")
    return n


def v_ui(b):
    u = dict(title=clean(b.get("title"), 60) or DEF_UI["title"], sub=clean(b.get("sub"), 80), brand=clean(b.get("brand"), 40) or DEF_UI["brand"], logo=clean(b.get("logo"), 2) or "F",
             acc=clean(b.get("acc"), 7), warn_days=num(b.get("warn_days"), 1, 15, "সতর্কতা দিন"), sync_seconds=num(b.get("sync_seconds"), 15, 3600, "সিঙ্ক ব্যবধান"),
             refresh=num(b.get("refresh"), 5, 300, "অটো-রিফ্রেশ"), seen_timeout=clean(b.get("seen_timeout"), 6), push_minutes=num(b.get("push_minutes"), 1, 1440, "পপ-আপ মিনিট"),
             session_hours=num(b.get("session_hours"), 1, 168, "সেশন ঘণ্টা"))
    if u["acc"] and not HEX.match(u["acc"]): raise ValueError("রং #RRGGBB ফরম্যাটে হতে হবে (বা ফাঁকা)")
    if not TMO.match(u["seen_timeout"]): raise ValueError('"বুঝেছি" সময় যেমন 3h বা 30m')
    return u


def v_popup(b):
    nums = []
    for n in (b.get("numbers") or [])[:4]:
        if not PHONE.match(clean(n.get("number"), 20)): raise ValueError("পেমেন্ট নম্বর ঠিক নয়")
        nums.append(dict(label=clean(n.get("label"), 30), number=clean(n.get("number"), 20), brand=clean(n.get("brand"), 20)))
    phone = clean(b.get("phone"), 20)
    if phone and not PHONE.match(phone): raise ValueError("ফোন নম্বর ঠিক নয়")
    cur = cfg_section("popup", DEF_POPUP); logo = cur.get("logo", "")
    if "logo" in b:
        logo = str(b.get("logo") or "")
        if logo and not (re.match(r"^data:image/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$", logo) and len(logo) < 300000): raise ValueError("লোগো ছবি ঠিক নয় বা বেশি বড়")
    return dict(numbers=nums, office=clean(b.get("office"), 120), phone=phone, logo=logo,
                warn_notice=clean(b.get("warn_notice"), 300), expired_notice=clean(b.get("expired_notice"), 300))


def v_access(b):
    d = clean(b.get("domain"), 253).lower()
    if d and not HOST.match(d): raise ValueError("ডোমেইন ঠিক নয় (যেমন bill.example.com)")
    try: return dict(domain=d, public_ip=ip4(clean(b.get("public_ip"), 15)), pc_ip=ip4(clean(b.get("pc_ip"), 15)))
    except ValueError: raise ValueError("IP ঠিকানা ঠিক নয়")


def admin_host_ok(h):
    if h in ADMIN_HOSTS: return True
    a = cfg_section("access", DEF_ACCESS)
    if h and h in (a["domain"], a["public_ip"], a["pc_ip"]): return True
    try:
        ip = ipaddress.ip_address(h); return ip.is_private or ip.is_loopback
    except ValueError: return False


def local_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); ips.add(s.getsockname()[0]); s.close()
    except Exception: pass
    try: ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except Exception: pass
    return sorted(i for i in ips if not i.startswith("127."))


def public_ip():
    try:
        v = urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode().strip(); ip4(v); return v
    except Exception: return ""


# ---------- লগইন / পাসওয়ার্ড ----------
AUTH, SESS, FAILS = BASE / "auth.json", {}, {}


def pw_hash(pw, salt): return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()
def now_s(): return time.strftime("%Y-%m-%d %H:%M")


def auth_load():
    with SET_LOCK:
        if AUTH.exists(): return json.loads(AUTH.read_text(encoding="utf-8"))
        salt = secrets.token_hex(16)
        a = dict(user=A["user"], salt=salt, hash=pw_hash(A["password"], salt), history=[dict(at=now_s(), ip="-", what="প্রাথমিক সেটআপ (config.ini থেকে)")])
        AUTH.write_text(json.dumps(a, ensure_ascii=False), encoding="utf-8")
        if A["password"].startswith("CHANGE_ME"): print("সতর্কতা: ডিফল্ট পাসওয়ার্ড! লগইন করে সেটিং > লগইন ও পাসওয়ার্ড থেকে এখনই বদলান।")
        return a


def auth_ok(user, pw):
    a = auth_load()
    return hmac.compare_digest(user.encode(), a["user"].encode()) & hmac.compare_digest(pw_hash(pw, a["salt"]), a["hash"])


def page(name, **kw):
    t = (BASE / name).read_text(encoding="utf-8")
    t = t.replace("__NAV__", (BASE / "nav.html").read_text(encoding="utf-8")).replace("__JS__", (BASE / "base.js").read_text(encoding="utf-8"))
    t = t.replace("__CSS__", (BASE / "base.css").read_text(encoding="utf-8")).replace("__THEME__", theme_css()).replace("__UI__", jdump(ui_public()))
    for k, v in kw.items(): t = t.replace(k, v)
    return t.encode("utf-8")


def jdump(o): return json.dumps(o, ensure_ascii=False).replace("</", "<\\/")

# ---------- পপ-আপ সার্ভার ----------
def esc(s): return _html.escape(str(s), quote=True)


def popup_parts(Pc):
    rows = ""
    for n in Pc["numbers"]:
        bk = f'<img class="bk" alt="" src="{ASSETS["bkash"]}" />' if n["brand"].lower() == "bkash" else ""
        lab = f'{bk}<span class="pay-brand">{esc(n["brand"])}</span>' + (f' · {esc(n["label"])}' if n["label"] else "")
        rows += (f'          <div class="payment-row"><div><div class="pay-label">{lab}</div><div class="pay-number">{esc(n["number"])}</div></div>'
                 f'<button class="copy" type="button" data-copy="{esc(re.sub(r"[^0-9+]", "", n["number"]))}">কপি</button></div>\n')
    call = ""
    if Pc["phone"]:
        call = ('<a class="call" href="tel:' + esc(re.sub(r"[^0-9+]", "", Pc["phone"])) + '"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
                '<path d="M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1 1 .4 1.9.7 2.8a2 2 0 0 1-.5 2.1L8.1 9.9a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.9.3 1.8.6 2.8.7a2 2 0 0 1 1.7 2z"/></svg>'
                f'যোগাযোগ করুনঃ {esc(Pc["phone"])}</a>')
    off = f'<div class="office"><b>অফিসঃ</b> {esc(Pc["office"])}</div>' if Pc["office"] else ""
    return dict(PAYMENTS=rows, LOGO=Pc.get("logo") or ASSETS["logo"], FOOTER=off + call)


ACK_BTN = ('<button class="ack" type="button" onclick="ack(this)">বুঝেছি</button>'
           "<script>function ack(b){fetch('/ack',{method:'POST'}).finally(()=>{b.textContent='ধন্যবাদ';setTimeout(()=>{history.length>1?history.back():window.close()},700)})}</script>")


def render(info):
    Pc = cfg_section("popup", DEF_POPUP)
    e = bn_date(info["exp"]) if info.get("exp") else ""
    if info["status"] == "manual":
        v = dict(TITLE="ইন্টারনেট বিল পরিশোধ করুন", SUBTITLE="JSN WiFi এর পক্ষ থেকে সতর্কবার্তা", BADGE=(f'<div class="badge">মেয়াদ শেষ: {e}</div>' if e else ""),
                 NOTICE=esc(info.get("msg") or Pc["warn_notice"]), ACK=ACK_BTN)
    elif info["status"] == "warn":
        n = info["left"]; when = "আগামীকাল" if n == 1 else f"{bn(n)} দিন পর"
        v = dict(TITLE="ইন্টারনেট বিল পরিশোধ করুন", SUBTITLE=f"আপনার সংযোগের মেয়াদ {when} শেষ হবে",
                 BADGE=f'<div class="badge">মেয়াদ শেষ: {e} · আর {bn(n)} দিন বাকি</div>', NOTICE=esc(Pc["warn_notice"]), ACK=ACK_BTN)
    else:
        v = dict(TITLE="ইন্টারনেট বিল পরিশোধ করুন", SUBTITLE="আপনার ইন্টারনেট সংযোগের মেয়াদ শেষ হয়েছে",
                 BADGE=f'<div class="badge red">মেয়াদ শেষ হয়েছে: {e}</div>', NOTICE=esc(Pc["expired_notice"]), ACK="")
    v.update(popup_parts(Pc)); v["CLS"] = "hasack" if v["ACK"] else ""
    page_ = TEMPLATE
    for k, val in v.items(): page_ = page_.replace("{{%s}}" % k, val)
    return page_.encode("utf-8")


def dashboard_data():
    today, users = dt.date.today(), []
    for u, d in load_full().items():
        st, left = classify(d["exp"], today)
        users.append(dict(u=u, last=d["last"].isoformat(), exp=d["exp"].isoformat(), left=left, st=st, pkg=d["pkg"],
                          ip=ACTIVE.get(u, ""), start=(d["exp"] - dt.timedelta(days=warn_days())).isoformat()))
    files = sorted(p.name for p in DATA_DIR.glob("*.csv"))
    full, online = load_full(), []
    with LOCK:
        al, man = list(ACTIVE_LIST), set(MANUAL)
    for r in al:
        d = full.get(r["name"])
        st, left = classify(d["exp"], today) if d else ("unknown", None)
        online.append(dict(u=r["name"], ip=r["address"], up=r["uptime"], mac=r["mac"], st=st, left=left, exp=d["exp"].isoformat() if d else "", manual=r["address"] in man))
    c = rs()
    rt = dict(host=c.get("host", ""), port=str(c.get("port", 8728)), user=c.get("user", ""), ssl=str(c.get("ssl", "")).lower() in ("1", "true", "yes"), has_pw=bool(c.get("password")) and c.get("password") != "CHANGE_ME")
    return dict(today=today.isoformat(), warn_days=warn_days(), ui=ui_public(), users=users, sync=dict(SYNC), files=files, online=online, router=rt)



def config_data():
    c, a = rs(), auth_load()
    return dict(router=dict(host=c.get("host", ""), port=str(c.get("port", 8728)), user=c.get("user", ""), ssl=str(c.get("ssl", "")).lower() in ("1", "true", "yes")),
                ui=ui(), popup=cfg_section("popup", DEF_POPUP), default_logo=ASSETS["logo"], access=cfg_section("access", DEF_ACCESS), account=dict(user=a["user"], history=a["history"][-30:]))


class H(BaseHTTPRequestHandler):
    def _info(self):
        with LOCK: return STATE.get(self.client_address[0])

    def _cip(self):
        p = self.client_address[0]
        xf = self.headers.get("X-Forwarded-For") if p in ("127.0.0.1", "::1") else None
        return xf.split(",")[0].strip() if xf else p

    def _send(self, body, ctype="text/html; charset=utf-8", code=200, extra=()):
        self.send_response(code)
        for k, v in (("Content-Type", ctype), ("Cache-Control", "no-store"), ("Content-Length", str(len(body)))) + tuple(extra): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def _json(self, o, code=200): self._send(jdump(o).encode(), "application/json; charset=utf-8", code, SEC)

    def _session(self):
        try: tok = SimpleCookie(self.headers.get("Cookie", ""))["jsn_sid"].value
        except Exception: return None, None
        s = SESS.get(tok)
        if s and s["exp"] > time.time():
            s["exp"] = time.time() + int(ui()["session_hours"]) * 3600; return tok, s
        SESS.pop(tok, None); return None, None

    def _cookie(self, tok, age):
        sec = "; Secure" if (self.headers.get("X-Forwarded-Proto") == "https") else ""
        return ("Set-Cookie", f"jsn_sid={tok}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age={age}{sec}")

    def _login(self):
        ip, now = self._cip(), time.time()
        f = FAILS.get(ip)
        if f and now - f[1] > 900: FAILS.pop(ip, None); f = None
        if f and f[0] >= 5:
            return self._json(dict(ok=False, error=f"অনেকবার ভুল হয়েছে; {int((900-(now-f[1]))//60)+1} মিনিট পরে চেষ্টা করুন"), 429)
        try: b = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 4000)) or b"{}")
        except Exception: b = {}
        if auth_ok(clean(b.get("user"), 80), str(b.get("password") or "")[:200]):
            FAILS.pop(ip, None); tok = secrets.token_urlsafe(32)
            SESS[tok] = dict(user=b["user"], exp=now + int(ui()["session_hours"]) * 3600)
            self._send(jdump(dict(ok=True)).encode(), "application/json", 200, SEC + (self._cookie(tok, 86400 * 7),))
        else:
            FAILS[ip] = ((f[0] + 1, f[1]) if f else (1, now)); time.sleep(0.6)
            self._json(dict(ok=False, error="ইউজার বা পাসওয়ার্ড ভুল"), 401)

    def _admin(self):
        url = urlparse(self.path)
        if not url.path.startswith("/admin") or not admin_host_ok((self.headers.get("Host") or "").split(":")[0]): return False
        post = self.command == "POST"
        if post and self.headers.get("X-Requested-With") != "jsn": self._json(dict(ok=False, error="forbidden"), 403); return True
        if post and url.path == "/admin/login": self._login(); return True
        tok, s = self._session()
        if not s:
            if post or url.path.startswith("/admin/api/"): self._json(dict(ok=False, error="লগইন করুন"), 401)
            else: self._send(page("login.html"), extra=SEC)
            return True
        p = url.path
        if post and p == "/admin/logout": SESS.pop(tok, None); self._send(b"{}", "application/json", 200, SEC + (self._cookie("", 0),))
        elif p.startswith("/admin/api/"): self._api(p, tok)
        elif post and p == "/admin/upload": self._upload(parse_qs(url.query).get("replace") == ["1"])
        elif p == "/admin/preview":
            m = parse_qs(url.query).get("mode", ["warn"])[0]
            self._send(render(dict(user="demo", status=m, left=2, exp=dt.date.today() + dt.timedelta(days=2))), extra=SEC)
        else: self._send(page("app.html", __DATA__=jdump(dashboard_data()), __CFG__=jdump(config_data()), __DEMO__="false"), extra=SEC)
        return True

    def _api(self, p, tok):
        try:
            n = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(min(n, 100000)) or b"{}") if self.command == "POST" else {}
            res = dict(ok=True)
            if p == "/admin/api/state": res = dashboard_data()
            elif p == "/admin/api/config": res = config_data()
            elif p == "/admin/api/refresh": sync_once(); res = dashboard_data()
            elif p == "/admin/api/netinfo": res = dict(local=local_ips(), public=public_ip())
            elif p == "/admin/api/push": push(clean(b["user"], 120), clean(b.get("msg"), 300), num(b.get("minutes", ui()["push_minutes"]), 1, 1440, "মিনিট"))
            elif p == "/admin/api/router":
                cur = cfg_all().copy()
                cur.update(host=clean(b["host"], 253), port=num(b.get("port") or 8728, 1, 65535, "পোর্ট"), user=clean(b["user"], 80), ssl=bool(b.get("ssl")))
                if b.get("password"): cur["password"] = str(b["password"])[:200]
                with SET_LOCK: SETTINGS.write_text(json.dumps(cur, ensure_ascii=False), encoding="utf-8"); _CACHE[0] = 0
                sync_once(); res = dict(ok=True, msg=SYNC["msg"])
            elif p == "/admin/api/ui": cfg_save("ui", v_ui(b))
            elif p == "/admin/api/popup": cfg_save("popup", v_popup(b))
            elif p == "/admin/api/access": cfg_save("access", v_access(b))
            elif p == "/admin/api/logout_others":
                for t in [t for t in SESS if t != tok]: del SESS[t]
            elif p == "/admin/api/account":
                a = auth_load()
                if not auth_ok(a["user"], str(b.get("current") or "")): raise ValueError("বর্তমান পাসওয়ার্ড ভুল")
                nu, npw, what = clean(b.get("new_user"), 40), str(b.get("new_password") or ""), []
                if nu and nu != a["user"]:
                    if len(nu) < 3: raise ValueError("ইউজারনেম কমপক্ষে ৩ অক্ষর")
                    a["user"] = nu; what.append("ইউজারনেম")
                if npw:
                    if len(npw) < 10: raise ValueError("পাসওয়ার্ড কমপক্ষে ১০ অক্ষর")
                    a["salt"] = secrets.token_hex(16); a["hash"] = pw_hash(npw, a["salt"]); what.append("পাসওয়ার্ড")
                if not what: raise ValueError("কিছু বদলানো হয়নি")
                a["history"].append(dict(at=now_s(), ip=self._cip(), what=" ও ".join(what) + " পরিবর্তন"))
                with SET_LOCK: AUTH.write_text(json.dumps(a, ensure_ascii=False), encoding="utf-8")
                for t in [t for t in SESS if t != tok]: del SESS[t]
            else: res = dict(ok=False, error="unknown")
        except Exception as ex:
            res = dict(ok=False, error=str(ex))
            if p == "/admin/api/router": SYNC.update(ok=False, msg=f"রাউটার সংযোগ ব্যর্থ: {ex}")
        self._json(res)

    def _upload(self, replace):
        try:
            raw = self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 10_000_000))
            rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
            good = [r for r in rows if (r.get("Date") or "").strip()]
            if not good or "User" not in good[0]: raise ValueError("CSV-তে Date ও User কলাম লাগবে")
            for r in good: dt.datetime.strptime(r["Date"].strip(), "%d-%b-%Y %I:%M:%S %p")
            DATA_DIR.mkdir(exist_ok=True)
            if replace:
                (DATA_DIR / "archive").mkdir(exist_ok=True)
                for f in DATA_DIR.glob("*.csv"): shutil.move(str(f), DATA_DIR / "archive" / f"{int(time.time())}_{f.name}")
            (DATA_DIR / time.strftime("upload_%Y%m%d_%H%M%S.csv")).write_bytes(raw)
            res = dict(ok=True, rows=len(good), users=len({r["User"].strip() for r in good}))
        except Exception as ex: res = dict(ok=False, error=str(ex))
        self._json(res)

    def do_GET(self):
        if self._admin(): return
        info = self._info()
        if not info: self.send_response(204); self.end_headers(); return   # তালিকায় নেই -> "ইন্টারনেট ঠিক আছে"
        self._send(render(info))

    do_HEAD = do_GET

    def do_POST(self):
        if self._admin(): return
        info = self._info()
        if self.path == "/ack" and info and info["status"] in ("warn", "manual"):
            try: ack(self.client_address[0])
            except Exception as ex: print("ack error:", ex)
        self.send_response(204); self.end_headers()

    def log_message(self, *a): pass


SEC = (("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"))

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "report":
        report(dt.date.fromisoformat(sys.argv[2]) if len(sys.argv) > 2 else dt.date.today())
    else:
        auth_load()
        threading.Thread(target=sync_loop, daemon=True).start()
        print("সার্ভার চালু, পোর্ট", P.get("port", 8080), "· ড্যাশবোর্ড: /admin")
        ThreadingHTTPServer(("0.0.0.0", int(P.get("port", 8080))), H).serve_forever()
