import sys, subprocess, importlib, importlib.util

_REQ = [("cryptography","cryptography"),("argon2","argon2-cffi"),("PIL","Pillow")]

def _boot():
    miss = [p for m,p in _REQ if not importlib.util.find_spec(m)]
    if not miss: return
    for fl in (["--quiet"],["--quiet","--break-system-packages"]):
        try:
            subprocess.check_call(
                [sys.executable,"-m","pip","install"]+fl+miss,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except: pass
    import tkinter as _tk, tkinter.messagebox as _mb
    r = _tk.Tk(); r.withdraw()
    _mb.showerror("NullPass", "Cannot install: " + " ".join(miss))
    r.destroy(); sys.exit(1)

_boot()

sys.set_int_max_str_digits(8600) #Changing the integer to be bigger. default: 4300

import tkinter as tk
from tkinter import messagebox, filedialog
import json, os, csv, secrets, string, time, math
import hashlib, hmac, struct, base64, platform
import webbrowser, ctypes, urllib.request, threading, re, shutil
from pathlib import Path
from datetime import datetime
from collections import Counter
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as _H

try:
    from argon2.low_level import hash_secret_raw as _a2, Type as _A2T
    HAS_A2 = True
except: HAS_A2 = False

IS_WIN  = platform.system() == "Windows"
IS_MAC  = platform.system() == "Darwin"
VER     = "1.2"
GITHUB  = "https://github.com/necouncil/NullPass"
SALT_SZ = 32
NON_SZ  = 12
DB_VER  = 4

LOCK_T = {"30s":30, "1m":60, "5m":300, "15m":900, "Never":0}
CLIP_T = {"15s":15, "30s":30, "60s":60, "Never":0}

CATS = [
    "General","Work","Finance","Social","Email",
    "Gaming","Crypto","Dev","Shopping","Travel","Health","Other"
]
SORTS = ["Name","Modified","Strength","Last used","Created"]

_LANG = "en"

TX = {
"en": {
    "unlock":"Unlock","create_vault":"Create Vault",
    "master_pw":"Master password","confirm_pw":"Confirm password",
    "welcome":"Welcome back","create_new":"Create your vault",
    "pw_warning":"Master password cannot be recovered if lost",
    "enc_info":"AES-256-GCM · Argon2id · stored locally",
    "search":"Search",
    "new":"New","generator":"Generator","audit":"Audit",
    "trash":"Trash","settings":"Settings","lock":"Lock",
    "all":"All","favorites":"Starred","pinned":"Pinned","weak":"Weak","twofa":"2FA",
    "no_entries":"No entries yet",
    "add_first":"Press New to add your first entry",
    "copy":"Copy","show":"Show","open":"Open",
    "edit":"Edit","delete":"Delete","save":"Save",
    "cancel":"Cancel","close":"Close","duplicate":"Duplicate",
    "username":"Username","password":"Password","url":"URL",
    "notes":"Notes","category":"Category","tags":"Tags","totp":"TOTP / 2FA",
    "custom_fields":"Custom fields","add_field":"+ Add field",
    "generate":"Random","passphrase":"Phrase","pin":"PIN","memorable":"Memorable",
    "length":"Length","uppercase":"A–Z","lowercase":"a–z","digits":"0–9","symbols":"#!@",
    "no_ambiguous":"No ambiguous","extra_syms":"Extended symbols",
    "strength":"Strength","bits":"bits","crack_time":"crack",
    "copied":"Copied","clears_in":"clears in",
    "last_used":"Last used","uses":"opens","created":"Created",
    "modified":"Modified","pw_changed":"PW changed",
    "sort_by":"Sort",
    "title_req":"Title is required","pw_req":"Password is required",
    "min8":"Minimum 8 characters","no_match":"Passwords do not match",
    "wrong_pw":"Wrong password","attempts_left":"attempts left",
    "too_many":"Too many attempts. Restart.",
    "audit_title":"Security Audit",
    "excellent":"Excellent","fair":"Fair","poor":"Needs work",
    "total":"Total","starred":"Starred","duplicates":"Duplicates","outdated":"Outdated",
    "same_pw":"reused","days_old":"90+ days",
    "weak_pws":"Weak passwords","dup_pws":"Reused passwords",
    "hibp":"Have I Been Pwned",
    "hibp_info":"Checks passwords against known breach databases.\nOnly the first 5 characters of the SHA1 hash are sent — your password never leaves this device.",
    "hibp_check":"Check all","hibp_progress":"Checking {i}/{n}",
    "hibp_ok":"All {n} checked — no breaches found.",
    "hibp_found":"{t} — found in {n:,} breaches",
    "trash_title":"Trash","trash_empty":"Trash is empty",
    "restore":"Restore","empty_trash":"Empty Trash",
    "empty_confirm":"Permanently delete all items in trash?",
    "del_confirm":"Move «{name}» to Trash?",
    "settings_title":"Settings","appearance":"Appearance","theme":"Theme",
    "dark":"Dark","light":"Light","lang":"Language",
    "restart_note":"Restart to apply.","security":"Security",
    "autolock":"Auto-lock","clip_clear":"Clipboard clear",
    "max_fail_lbl":"Max unlock attempts","unlimited":"Unlimited",
    "encryption":"Encryption","change_master":"Change master password",
    "current_pw":"Current password","new_pw":"New password",
    "confirm_new":"Confirm new","change":"Update","pw_ok":"Password updated.",
    "data":"Import & Export","export":"Export","import_":"Import",
    "exp_csv":"Export CSV","exp_enc":"Export .npx",
    "imp_csv":"Import CSV","imp_enc":"Import .npx",
    "exp_pw":"Set export password:","imp_pw":"File password:",
    "exported":"Exported {n} entries","imported":"Imported {n} entries",
    "backup":"Backup","create_bk":"Create Backup",
    "open_folder":"Open Folder","bk_saved":"Saved: {name}",
    "bk_found":"{n} backup(s) · latest: {name}",
    "vault_file":"Vault file","about":"About",
    "restart_req":"Restart required. Restart now?",
    "pw_history":"Password history","restore_pw":"Restore",
    "test":"Test","totp_ok":"Code: {code}\nValid: {rem}s","totp_err":"TOTP Error",
    "dup_ok":"Duplicated: {t}","unlocking":"Unlocking…","creating":"Creating vault…",
    "regen":"Regenerate","use_this":"Use","recent":"Recent","clear":"clear",
    "phrase_words":"Words","sep":"Sep","cap":"Cap","num":"Num","pin_length":"PIN length",
    "selected":"selected","entry_info":"Entry info",
},
"ru": {
    "unlock":"Открыть","create_vault":"Создать хранилище",
    "master_pw":"Мастер-пароль","confirm_pw":"Подтверждение",
    "welcome":"Добро пожаловать","create_new":"Создайте хранилище",
    "pw_warning":"Мастер-пароль нельзя восстановить при потере",
    "enc_info":"AES-256-GCM · Argon2id · хранится локально",
    "search":"Поиск",
    "new":"Новая","generator":"Генератор","audit":"Аудит",
    "trash":"Корзина","settings":"Настройки","lock":"Блокировка",
    "all":"Все","favorites":"Избранное","pinned":"Закреплённые","weak":"Слабые","twofa":"2FA",
    "no_entries":"Записей нет",
    "add_first":"Нажмите «Новая» для добавления",
    "copy":"Копировать","show":"Показать","open":"Открыть",
    "edit":"Изменить","delete":"Удалить","save":"Сохранить",
    "cancel":"Отмена","close":"Закрыть","duplicate":"Дублировать",
    "username":"Логин","password":"Пароль","url":"URL / Сайт",
    "notes":"Заметки","category":"Категория","tags":"Теги","totp":"TOTP / 2FA",
    "custom_fields":"Свои поля","add_field":"+ Добавить поле",
    "generate":"Случайный","passphrase":"Фраза","pin":"PIN","memorable":"Запоминаемый",
    "length":"Длина","uppercase":"A–Z","lowercase":"a–z","digits":"0–9","symbols":"#!@",
    "no_ambiguous":"Без похожих","extra_syms":"Доп. символы",
    "strength":"Надёжность","bits":"бит","crack_time":"взлом",
    "copied":"Скопировано","clears_in":"очистится через",
    "last_used":"Открывали","uses":"открытий","created":"Создано",
    "modified":"Изменено","pw_changed":"Пароль изменён",
    "sort_by":"Сортировка",
    "title_req":"Введите название","pw_req":"Введите пароль",
    "min8":"Минимум 8 символов","no_match":"Пароли не совпадают",
    "wrong_pw":"Неверный пароль","attempts_left":"попыток",
    "too_many":"Слишком много попыток. Перезапустите.",
    "audit_title":"Аудит безопасности",
    "excellent":"Отлично","fair":"Нормально","poor":"Нужна работа",
    "total":"Всего","starred":"Избранных","duplicates":"Дублей","outdated":"Устаревших",
    "same_pw":"одинаковый","days_old":"90+ дней",
    "weak_pws":"Слабые пароли","dup_pws":"Повторяющиеся пароли",
    "hibp":"Have I Been Pwned",
    "hibp_info":"Проверяет по базам утечек.\nПересылаются только первые 5 символов SHA1 — пароль не покидает устройство.",
    "hibp_check":"Проверить","hibp_progress":"Проверяю {i}/{n}",
    "hibp_ok":"Проверено {n} — утечек нет.",
    "hibp_found":"{t} — найден в {n:,} утечках",
    "trash_title":"Корзина","trash_empty":"Корзина пуста",
    "restore":"Восстановить","empty_trash":"Очистить корзину",
    "empty_confirm":"Навсегда удалить все элементы корзины?",
    "del_confirm":"Переместить «{name}» в корзину?",
    "settings_title":"Настройки","appearance":"Оформление","theme":"Тема",
    "dark":"Тёмная","light":"Светлая","lang":"Язык",
    "restart_note":"Нужен перезапуск.","security":"Безопасность",
    "autolock":"Автоблокировка","clip_clear":"Очистка буфера",
    "max_fail_lbl":"Макс. попыток","unlimited":"Без ограничений",
    "encryption":"Шифрование","change_master":"Изменить мастер-пароль",
    "current_pw":"Текущий пароль","new_pw":"Новый пароль",
    "confirm_new":"Подтверждение","change":"Изменить","pw_ok":"Пароль изменён.",
    "data":"Импорт и экспорт","export":"Экспорт","import_":"Импорт",
    "exp_csv":"Экспорт CSV","exp_enc":"Экспорт .npx",
    "imp_csv":"Импорт CSV","imp_enc":"Импорт .npx",
    "exp_pw":"Пароль для экспорта:","imp_pw":"Пароль файла:",
    "exported":"Экспортировано {n} записей","imported":"Импортировано {n} записей",
    "backup":"Резервная копия","create_bk":"Создать копию",
    "open_folder":"Открыть папку","bk_saved":"Сохранено: {name}",
    "bk_found":"{n} копий · последняя: {name}",
    "vault_file":"Файл хранилища","about":"О программе",
    "restart_req":"Нужен перезапуск. Перезапустить сейчас?",
    "pw_history":"История паролей","restore_pw":"Вернуть",
    "test":"Тест","totp_ok":"Код: {code}\nДействует: {rem}с","totp_err":"Ошибка TOTP",
    "dup_ok":"Скопировано: {t}","unlocking":"Открываю…","creating":"Создаю хранилище…",
    "regen":"Ещё","use_this":"Использовать","recent":"Недавние","clear":"очистить",
    "phrase_words":"Слов","sep":"Разд","cap":"Загл","num":"Цифры","pin_length":"Длина PIN",
    "selected":"выбрано","entry_info":"Информация",
}}

def T(k, **kw):
    v = TX.get(_LANG, TX["en"]).get(k, TX["en"].get(k, k))
    return v.format(**kw) if kw else v

DARK = {
    "bg":    "#0a0a0a", "bg2":   "#101010", "bg3":   "#151515",
    "bg4":   "#1a1a1a", "bg5":   "#202020", "bg6":   "#2a2a2a",
    "line":  "#1e1e1e", "line2": "#242424", "line3": "#2e2e2e",
    "fg":    "#f2f2f2", "fg2":   "#888888", "fg3":   "#444444", "fg4":   "#222222",
    "acc":   "#e11d48", "acc2":  "#be123c", "acc_t": "#ffffff",
    "green": "#22c55e", "amber": "#f59e0b", "sky":   "#38bdf8", "red":   "#ef4444",
    "s0":    "#ef4444", "s1":    "#f59e0b", "s2":    "#f59e0b",
    "s3":    "#22c55e", "s4":    "#f2f2f2",
    "tag_bg":"#151515", "tag_fg":"#555555",
    "inp":   "#0d0d0d", "inp_b": "#222222",
    "sel":   "#1a0a0e", "sel_fg":"#f2f2f2",
    "card":  "#111111", "hover": "#161616",
    "btn":   "#151515", "btn_h": "#1e1e1e", "btn_fg":"#666666",
    "sb":    "#0a0a0a",
}
LIGHT = {
    "bg":    "#fafafa", "bg2":   "#ffffff", "bg3":   "#f4f4f4",
    "bg4":   "#ececec", "bg5":   "#e4e4e4", "bg6":   "#d8d8d8",
    "line":  "#e4e4e4", "line2": "#d8d8d8", "line3": "#cccccc",
    "fg":    "#0a0a0a", "fg2":   "#444444", "fg3":   "#999999", "fg4":   "#e0e0e0",
    "acc":   "#e11d48", "acc2":  "#be123c", "acc_t": "#ffffff",
    "green": "#16a34a", "amber": "#d97706", "sky":   "#0284c7", "red":   "#dc2626",
    "s0":    "#dc2626", "s1":    "#d97706", "s2":    "#d97706",
    "s3":    "#16a34a", "s4":    "#0a0a0a",
    "tag_bg":"#f0f0f0", "tag_fg":"#666666",
    "inp":   "#ffffff", "inp_b": "#d0d0d0",
    "sel":   "#ffeef2", "sel_fg":"#0a0a0a",
    "card":  "#ffffff", "hover": "#fafafa",
    "btn":   "#f0f0f0", "btn_h": "#e8e8e8", "btn_fg":"#444444",
    "sb":    "#fafafa",
}

_PAL = dict(DARK)
_THEME_NAME = "dark"

def _c(k): return _PAL.get(k, "#ff00ff")

def _apply(name):
    global _THEME_NAME
    _THEME_NAME = name
    _PAL.clear()
    _PAL.update(DARK if name == "dark" else LIGHT)

def _ff():
    if IS_WIN: return "Segoe UI"
    if IS_MAC: return "SF Pro Display"
    return "Ubuntu"

def _fm():
    if IS_WIN: return "Consolas"
    if IS_MAC: return "SF Mono"
    return "Ubuntu Mono"

def F(s=11, b=False, m=False):
    return (_fm() if m else _ff(), s, "bold" if b else "normal")

def _data():
    base = Path(os.environ.get("APPDATA", Path.home())) if IS_WIN else Path.home()/".local"/"share"
    d = base/"NullPass"; d.mkdir(parents=True, exist_ok=True); return d

def _cfg(): return _data()/"config.json"

def _lcfg():
    try: return json.loads(_cfg().read_text("utf-8"))
    except: return {}

def _scfg(c):
    try: _cfg().write_text(json.dumps(c, indent=2), "utf-8")
    except: pass

def _restart():
    _scfg(_lcfg())
    os.execv(sys.executable, [sys.executable]+sys.argv)

def _kdf(pwd, salt):
    if HAS_A2:
        return _a2(secret=pwd.encode(), salt=salt, time_cost=4,
                   memory_cost=131072, parallelism=4, hash_len=32, type=_A2T.ID)
    k = PBKDF2HMAC(algorithm=_H.SHA256(), length=32, salt=salt, iterations=600000)
    return k.derive(pwd.encode())

def _enc(d, k):
    n = secrets.token_bytes(NON_SZ)
    return n + AESGCM(k).encrypt(n, d, None)

def _dec(d, k):
    return AESGCM(k).decrypt(d[:NON_SZ], d[NON_SZ:], None)

def _wipe(b):
    if not b: return
    try:
        if isinstance(b, bytearray):
            for i in range(len(b)): b[i] = 0
        else:
            m = (ctypes.c_char*len(b)).from_buffer_copy(b)
            ctypes.memset(m, 0, len(b))
    except: pass

SYMS  = "!@#$%^&*-_=+?<>"
SYMSX = "!@#$%^&*-_=+?<>~|{}[]"
WL = [
    "apple","brave","cloud","dream","eagle","flame","grace","house","ivory","jewel",
    "kings","light","magic","night","ocean","pearl","queen","river","storm","tiger",
    "ultra","valor","winds","xenon","amber","bison","cedar","delta","ember","frost",
    "giant","honor","joker","karma","lemon","maple","noble","oasis","piano","quake",
    "radar","solar","tower","umbra","viper","waltz","pixel","alpha","blade","crane",
    "drift","elite","forge","globe","helix","knife","lunar","mount","north","opera",
    "prism","rocky","stone","trail","unity","venus","water","yacht","cipher","token",
    "shard","nexus","flux","echo","falcon","grove","haven","lance","mist","nova",
    "orbit","phase","quest","rune","sage","thorn","vault","zeal","swift","blaze",
]

def mkpw(n=20, up=True, lo=True, dg=True, sy=True, noamb=False, xsym=False):
    sym = SYMSX if xsym else SYMS
    amb = "O0lI1"
    def p(c): return c.translate(str.maketrans("","",amb)) if noamb else c
    UP=p(string.ascii_uppercase); LO=p(string.ascii_lowercase); DG=p(string.digits)
    pool, must = "", []
    if up and UP: pool+=UP; must.append(secrets.choice(UP))
    if lo and LO: pool+=LO; must.append(secrets.choice(LO))
    if dg and DG: pool+=DG; must.append(secrets.choice(DG))
    if sy:        pool+=sym; must.append(secrets.choice(sym))
    if not pool: pool = string.ascii_letters+string.digits
    fill = [secrets.choice(pool) for _ in range(max(0, n-len(must)))]
    r = must+fill; secrets.SystemRandom().shuffle(r); return "".join(r)

def mkphrase(w=4, sep="-", cap=False, num=True):
    p = [secrets.choice(WL) for _ in range(w)]
    if cap: p = [x.capitalize() for x in p]
    r = sep.join(p)
    if num: r += str(secrets.randbelow(9999)).zfill(4)
    return r

def pw_str(pw):
    if not pw: return 0, "", _c("fg4")
    s = min(30, len(pw)*2)
    if any(c.isupper() for c in pw): s += 15
    if any(c.islower() for c in pw): s += 10
    if any(c.isdigit() for c in pw): s += 15
    if any(c in SYMSX for c in pw):  s += 20
    if len(set(pw)) >= len(pw)*0.7:  s += 10
    s = min(s, 100)
    i = 0 if s<30 else 1 if s<50 else 2 if s<70 else 3 if s<88 else 4
    return s, ["Very Weak","Weak","Fair","Strong","Excellent"][i], _c(f"s{i}")

def entropy(pw):
    if not pw: return 0.0
    pool = sum([
        26 if any(c.isupper() for c in pw) else 0,
        26 if any(c.islower() for c in pw) else 0,
        10 if any(c.isdigit() for c in pw) else 0,
        len(SYMSX) if any(c in SYMSX for c in pw) else 0,
    ]) or 26
    return round(len(pw)*math.log2(pool), 1)

def crack(bits):
    if not bits: return ""
    s = 2**bits/1e10
    if s<1: return "<1s"
    if s<60: return f"{int(s)}s"
    if s<3600: return f"{int(s/60)}m"
    if s<86400: return f"{int(s/3600)}h"
    if s<31536000: return f"{int(s/86400)}d"
    y = s/31536000
    if y<1e6: return f"{y:,.0f}y"
    if y<1e9: return f"{y/1e6:.1f}My"
    return "∞"

def do_totp(secret):
    pad = (8-len(secret)%8)%8
    kb  = base64.b32decode(secret.upper().replace(" ","")+("="*pad))
    t   = int(time.time())//30
    h   = hmac.new(kb, struct.pack(">Q",t), hashlib.sha1).digest()
    off = h[-1]&0xF
    code = (struct.unpack(">I",h[off:off+4])[0]&0x7FFFFFFF)%1000000
    return f"{code:06d}", 30-int(time.time())%30

def check_breach(pw):
    try:
        sha = hashlib.sha1(pw.encode()).hexdigest().upper()
        pre, suf = sha[:5], sha[5:]
        req = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{pre}",
            headers={"Add-Padding":"true","User-Agent":f"NullPass/{VER}"})
        with urllib.request.urlopen(req, timeout=6) as r: body=r.read().decode()
        for line in body.splitlines():
            h, cnt = line.split(":")
            if h == suf: return int(cnt)
        return 0
    except: return None

def enc_blob(entries, pw):
    salt=secrets.token_bytes(SALT_SZ); key=_kdf(pw,salt)
    blob=json.dumps({"v":DB_VER,"entries":entries},ensure_ascii=False).encode()
    return bytes([DB_VER])+salt+_enc(blob,key)

def dec_blob(data, pw):
    salt=data[1:SALT_SZ+1]; key=_kdf(pw,salt)
    return json.loads(_dec(data[SALT_SZ+1:],key).decode())

def _dom(url):
    if not url: return ""
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1) if m else ""

def _ago(iso):
    try: return (datetime.now()-datetime.fromisoformat(iso)).days
    except: return 0

def _fmt(iso):
    try: return datetime.fromisoformat(iso).strftime("%d %b %Y")
    except: return ""


class Vault:
    def __init__(self):
        self.path    = _data()/"vault.np"
        self.key     = None; self.salt=None
        self.entries = []; self._trash=[]
        self._at     = 0.0; self._locked=True
        self.fails   = 0;   self._pwh=b""
        self._reload()

    def _reload(self):
        c = _lcfg()
        self._lock_s  = LOCK_T.get(c.get("lock_after","5m"), 300)
        self._clip_s  = CLIP_T.get(c.get("clip_after","30s"), 30)
        self.max_fail = int(c.get("max_fail", 5))

    def exists(self):  return self.path.exists()
    def locked(self):  return self._locked
    def touch(self):   self._at = time.time()

    def idle(self):
        return self._lock_s>0 and not self._locked and (time.time()-self._at)>self._lock_s

    def create(self, pw):
        self.salt=secrets.token_bytes(SALT_SZ); self.key=bytearray(_kdf(pw,self.salt))
        self._pwh=hashlib.sha256(pw.encode()).digest()
        self.entries=[]; self._trash=[]; self._locked=False; self.touch(); self._write()

    def unlock(self, pw):
        if self.fails >= self.max_fail: return False
        try:
            raw=self.path.read_bytes(); salt=raw[1:SALT_SZ+1]
            key=_kdf(pw,salt); plain=_dec(raw[SALT_SZ+1:],key)
            data=json.loads(plain.decode())
            if self.key: _wipe(self.key)
            self.salt=salt; self.key=bytearray(key)
            self._pwh=hashlib.sha256(pw.encode()).digest()
            self.entries=data.get("entries",[]); self._trash=data.get("trash",[])
            self._locked=False; self.fails=0; self.touch(); return True
        except: self.fails+=1; return False

    def verify(self, pw):
        if self._pwh:
            return hmac.compare_digest(hashlib.sha256(pw.encode()).digest(), self._pwh)
        try:
            raw=self.path.read_bytes()
            _dec(raw[SALT_SZ+1:], _kdf(pw,raw[1:SALT_SZ+1])); return True
        except: return False

    def change_pw(self, old, new):
        if not self.verify(old): return False
        self.salt=secrets.token_bytes(SALT_SZ)
        if self.key: _wipe(self.key)
        self.key=bytearray(_kdf(new,self.salt))
        self._pwh=hashlib.sha256(new.encode()).digest()
        self._write(); return True

    def lock(self):
        if self.key: _wipe(self.key)
        self.key=None; self.entries=[]; self._trash=[]; self._locked=True; self._pwh=b""

    def _write(self):
        data={"v":DB_VER,"entries":self.entries,"trash":self._trash}
        blob=json.dumps(data,ensure_ascii=False).encode()
        ct=_enc(blob,bytes(self.key))
        tmp=self.path.with_suffix(".tmp")
        tmp.write_bytes(bytes([DB_VER])+self.salt+ct)
        tmp.replace(self.path)

    def save(self):
        if not self._locked: self._write(); self.touch()

    def backup(self):
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = _data()/f"vault_backup_{ts}.np"
        shutil.copy2(self.path, dst); return dst

    def list_backups(self):
        return sorted(_data().glob("vault_backup_*.np"), reverse=True)

    def _now(self): return datetime.now().isoformat()

    def add(self, **kw):
        now = self._now()
        e = {
            "id":       secrets.token_hex(12),
            "title":    kw.get("title",""),
            "username": kw.get("username",""),
            "password": kw.get("password",""),
            "url":      kw.get("url",""),
            "notes":    kw.get("notes",""),
            "category": kw.get("category","General"),
            "tags":     kw.get("tags",[]),
            "totp":     kw.get("totp",""),
            "custom_fields": kw.get("custom_fields",[]),
            "favorite": False, "pinned": False,
            "created":  now, "modified": now, "pw_changed": now,
            "history":  [], "use_count": 0, "last_used": None,
        }
        self.entries.append(e); self.save(); return e

    def update(self, eid, **kw):
        for e in self.entries:
            if e["id"]==eid:
                if "password" in kw and kw["password"]!=e["password"]:
                    e.setdefault("history",[]).append({"pw":e["password"],"when":self._now()})
                    e["history"]=e["history"][-20:]; kw["pw_changed"]=self._now()
                e.update(kw); e["modified"]=self._now(); break
        self.save()

    def touch_entry(self, eid):
        for e in self.entries:
            if e["id"]==eid:
                e["use_count"]=e.get("use_count",0)+1; e["last_used"]=self._now(); break
        self.save()

    def delete(self, eid):
        entry=next((e for e in self.entries if e["id"]==eid), None)
        if entry:
            entry["deleted_at"]=self._now(); self._trash.append(entry)
            self._trash=self._trash[-50:]
        self.entries=[e for e in self.entries if e["id"]!=eid]; self.save()

    def restore(self, eid):
        e=next((x for x in self._trash if x["id"]==eid), None)
        if e:
            e.pop("deleted_at",None); self.entries.append(e)
            self._trash=[x for x in self._trash if x["id"]!=eid]; self.save()

    def empty_trash(self): self._trash=[]; self.save()

    def toggle_fav(self, eid):
        for e in self.entries:
            if e["id"]==eid: e["favorite"]=not e.get("favorite",False); break
        self.save()

    def toggle_pin(self, eid):
        for e in self.entries:
            if e["id"]==eid: e["pinned"]=not e.get("pinned",False); break
        self.save()

    def duplicate(self, eid):
        src=next((e for e in self.entries if e["id"]==eid), None)
        if not src: return None
        kw={k:src[k] for k in("title","username","password","url","notes",
                               "category","tags","totp","custom_fields")}
        kw["title"]+=" (copy)"; return self.add(**kw)

    def move_cat(self, ids, cat):
        for e in self.entries:
            if e["id"] in ids: e["category"]=cat
        self.save()

    def search(self, q):
        if not q: return list(self.entries)
        q = q.lower()
        return [e for e in self.entries
                if q in e.get("title","").lower()
                or q in e.get("username","").lower()
                or q in e.get("url","").lower()
                or q in e.get("notes","").lower()
                or q in e.get("category","").lower()
                or any(q in t.lower() for t in e.get("tags",[]))
                or any(q in cf.get("label","").lower() or q in cf.get("value","").lower()
                       for cf in e.get("custom_fields",[]))]

    def sort(self, entries, by):
        def key(e):
            base = (not e.get("pinned"), not e.get("favorite"))
            if by=="Modified":  return base+(e.get("modified",""),)
            if by=="Strength":  return base+(pw_str(e.get("password",""))[0],)
            if by=="Last used": return base+(e.get("last_used") or "",)
            if by=="Created":   return base+(e.get("created",""),)
            return base+(e.get("title","").lower(),)
        return sorted(entries, key=key)

    def stats(self):
        pws   = [e["password"] for e in self.entries if e.get("password")]
        dupes = len(pws)-len(set(pws))
        weak  = sum(1 for p in pws if pw_str(p)[0]<50)
        old   = sum(1 for e in self.entries if _ago(e.get("pw_changed",e.get("modified","")))>90)
        return {
            "total":   len(self.entries),
            "fav":     sum(1 for e in self.entries if e.get("favorite")),
            "dupes":   dupes, "weak": weak, "old": old,
            "with_2fa":sum(1 for e in self.entries if e.get("totp","").strip()),
            "trash":   len(self._trash),
        }

    def get_cats(self):
        c = sorted(set(e.get("category","General") for e in self.entries))
        return c if c else ["General"]

    def export_csv(self, path):
        with open(path,"w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=["title","username","password","url","notes","category","tags","totp"])
            w.writeheader()
            for e in self.entries:
                w.writerow({
                    "title":e.get("title",""), "username":e.get("username",""),
                    "password":e.get("password",""), "url":e.get("url",""),
                    "notes":e.get("notes",""), "category":e.get("category",""),
                    "tags":",".join(e.get("tags",[])), "totp":e.get("totp",""),
                })

    def export_enc(self, path, pw):
        Path(path).write_bytes(enc_blob(self.entries, pw))

    def import_csv(self, path):
        added = 0
        with open(path,newline="",encoding="utf-8") as f:
            for row in csv.DictReader(f):
                t=(row.get("title","") or row.get("name","") or row.get("Title","")).strip()
                p=(row.get("password","") or row.get("Password","")).strip()
                if not t: #If there no title we can try to take the url and not to put backspace because in the program you just see cleard lines but you can choose, to not edit every title and adding our we take to url and put to title
                    url = row.get("url","").strip()
                    if url:
                        t = url.split("//")[-1].split("/")[0]
                if not t: continue #If we also can't find any title we can do a cleared line
                tags=[x.strip() for x in row.get("tags","").split(",") if x.strip()]
                self.add(
                    title=t,
                    username=(row.get("username","") or row.get("login","")).strip(),
                    password=p, url=row.get("url","").strip(),
                    notes=row.get("notes","").strip(),
                    category=(row.get("category","Import") or "Import").strip(),
                    tags=tags, totp=row.get("totp","").strip(),
                ); added+=1
        return added

    def import_enc(self, path, pw):
        data=dec_blob(Path(path).read_bytes(), pw)
        ex={e["id"] for e in self.entries}; added=0
        for e in data.get("entries",[]):
            if e.get("id") not in ex:
                self.add(**{k:e[k] for k in("title","username","password","url","notes",
                             "category","tags","totp","custom_fields") if k in e})
                added+=1
        return added


def _mk_icon(size=32):
    try:
        from PIL import Image, ImageDraw
        img=Image.new("RGBA",(size,size),(0,0,0,0))
        d=ImageDraw.Draw(img)
        r=int(size*0.22)
        def rr(x1,y1,x2,y2,rad,fill):
            d.rectangle([x1+rad,y1,x2-rad,y2],fill=fill)
            d.rectangle([x1,y1+rad,x2,y2-rad],fill=fill)
            for cx,cy in[(x1,y1),(x2-2*rad,y1),(x1,y2-2*rad),(x2-2*rad,y2-2*rad)]:
                d.ellipse([cx,cy,cx+2*rad,cy+2*rad],fill=fill)
        rr(0,0,size-1,size-1,r,(10,10,10,255))
        rr(0,0,size-1,size-1,r,(225,29,72,255))
        bx1,by1=int(size*0.19),int(size*0.44)
        bx2,by2=int(size*0.81),int(size*0.87)
        br=max(3,int(size*0.07))
        rr(bx1,by1,bx2,by2,br,(10,10,10,255))
        cx=size//2; cy=(by1+by2)//2-int(size*0.02)
        cr=max(3,int(size*0.075))
        d.ellipse([cx-cr,cy-cr,cx+cr,cy+cr],fill=(225,29,72,255))
        tw=max(1,int(size*0.038)); th=int(size*0.10)
        d.rectangle([cx-tw,cy+int(size*0.01),cx+tw,cy+th],fill=(225,29,72,255))
        dr=int(size*0.042)
        d.ellipse([cx-dr,cy-dr,cx+dr,cy+dr],fill=(10,10,10,255))
        aw=int(size*0.22); sw=max(2,int(size*0.05))
        at=int(size*0.10); ab=at+int(aw*2.1)
        d.arc([cx-aw,at,cx+aw,ab],start=208,end=332,fill=(10,10,10,255),width=sw)
        return img
    except: return None

def _icon(size=32):
    try:
        from PIL import ImageTk
        img=_mk_icon(size)
        if img: return ImageTk.PhotoImage(img)
    except: pass
    return None


class _Ent(tk.Entry):
    def __init__(self, p, ph="", show="", **kw):
        self._ph=ph; self._show=show; self._ph_on=False
        o=dict(bg=_c("inp"), fg=_c("fg"), insertbackground=_c("fg"),
               relief="flat", bd=0, font=F(11),
               highlightthickness=1, highlightbackground=_c("inp_b"),
               highlightcolor=_c("acc"), show=show)
        o.update(kw); super().__init__(p, **o)
        if ph: self._dp(); self.bind("<FocusIn>",self._fi); self.bind("<FocusOut>",self._fo)
        self.bind("<Control-a>", lambda ev: (self.select_range(0,tk.END),"break")[1])

    def _dp(self):
        self.delete(0,tk.END); self.insert(0,self._ph)
        self.config(fg=_c("fg3"), show=""); self._ph_on=True

    def _fi(self, ev):
        if self._ph_on: self.delete(0,tk.END); self.config(fg=_c("fg"),show=self._show); self._ph_on=False

    def _fo(self, ev):
        if not self.get(): self._dp()

    def val(self): return "" if self._ph_on else self.get()

    def set_val(self, v):
        self._ph_on=False; self.delete(0,tk.END)
        self.config(fg=_c("fg"), show=self._show); self.insert(0,v)


class _Btn(tk.Label):
    def __init__(self, p, text, cmd, bg=None, fg=None, hov=None,
                 px=12, py=7, fs=10, bold=False, **kw):
        self._bg=bg or _c("btn"); self._fg=fg or _c("btn_fg"); self._hov=hov or _c("btn_h")
        super().__init__(p, text=text, bg=self._bg, fg=self._fg,
                         font=F(fs,bold), padx=px, pady=py, cursor="hand2", **kw)
        self.bind("<Enter>", lambda ev: self.config(bg=self._hov, fg=_c("fg")))
        self.bind("<Leave>", lambda ev: self.config(bg=self._bg,  fg=self._fg))
        self.bind("<Button-1>", lambda ev: cmd())


class _ABt(tk.Label):
    def __init__(self, p, text, cmd, py=9, danger=False, sm=False, **kw):
        fs=9 if sm else 10
        if danger: bg,fg,h="#150008",_c("acc"),"#200010"
        else:      bg,fg,h=_c("acc"),_c("acc_t"),_c("acc2")
        self._bg=bg; self._h=h
        super().__init__(p, text=text, bg=bg, fg=fg,
                         font=F(fs,b=True), padx=14, pady=py, cursor="hand2", **kw)
        self.bind("<Enter>", lambda ev: self.config(bg=self._h))
        self.bind("<Leave>", lambda ev: self.config(bg=self._bg))
        self.bind("<Button-1>", lambda ev: cmd())


class _SBar(tk.Canvas):
    def __init__(self, p, h=3, **kw):
        super().__init__(p, height=h, bg=_c("line"), highlightthickness=0, **kw)
        self._h=h

    def refresh(self, pw):
        sc,lb,col=pw_str(pw); self.delete("all")
        w=self.winfo_width() or 300; f=int(w*min(sc,100)/100)
        if f>0: self.create_rectangle(0,0,f,self._h,fill=col,outline="")
        return sc,lb,col


class _SF(tk.Frame):
    def __init__(self, p, bg=None, **kw):
        bg=bg or _c("bg"); super().__init__(p, bg=bg, **kw)
        self._bg=bg; self._wid=None
        self._sb=tk.Scrollbar(self, orient="vertical", width=4,
                              bg=_c("sb"), troughcolor=_c("bg"),
                              activebackground=_c("bg4"))
        self._sb.pack(side="right", fill="y")
        self._cv=tk.Canvas(self, bg=bg, highlightthickness=0,
                           yscrollcommand=self._sb.set)
        self._cv.pack(side="left", fill="both", expand=True)
        self._sb.config(command=self._cv.yview)
        self.inner=tk.Frame(self._cv, bg=bg)
        self.inner.bind("<Configure>", self._on_inner)
        self._cv.bind("<Configure>", self._on_cv)
        self.bind("<Map>", self._on_map, add="+")
        self._cv.bind("<Enter>", self._bon)
        self._cv.bind("<Leave>", self._boff)

    def _on_map(self, ev=None):
        if self._wid is None:
            self._wid=self._cv.create_window((0,0), window=self.inner, anchor="nw")
            self._cv.itemconfig(self._wid, width=max(1,self._cv.winfo_width()))
            self._cv.configure(scrollregion=self._cv.bbox("all") or (0,0,1,1))

    def _on_inner(self, ev=None):
        self._cv.configure(scrollregion=self._cv.bbox("all") or (0,0,1,1))

    def _on_cv(self, ev):
        if self._wid: self._cv.itemconfig(self._wid, width=ev.width)
        elif self._wid is None: self._on_map()

    def _bon(self, ev=None):
        self._cv.bind_all("<MouseWheel>", self._mw)
        self._cv.bind_all("<Button-4>", lambda e: self._cv.yview_scroll(-1,"units"))
        self._cv.bind_all("<Button-5>", lambda e: self._cv.yview_scroll(1,"units"))

    def _boff(self, ev=None):
        try:
            self._cv.unbind_all("<MouseWheel>")
            self._cv.unbind_all("<Button-4>")
            self._cv.unbind_all("<Button-5>")
        except: pass

    def _mw(self, ev): self._cv.yview_scroll(int(-1*(ev.delta/120)),"units")


def _div(p, px=0, py=0):
    f=tk.Frame(p, bg=_c("line"), height=1)
    f.pack(fill="x", padx=px, pady=py) if px else f.pack(fill="x", pady=py)


def _tip(w, text):
    _t=[None]
    def show(ev):
        _t[0]=tk.Toplevel(w); _t[0].wm_overrideredirect(True)
        _t[0].wm_geometry(f"+{ev.x_root+14}+{ev.y_root+12}")
        tk.Label(_t[0], text=text, bg=_c("bg4"), fg=_c("fg2"), font=F(8),
                 padx=7, pady=4, highlightthickness=1,
                 highlightbackground=_c("line2")).pack()
    def hide(ev=None):
        if _t[0]:
            try: _t[0].destroy()
            except: pass
            _t[0]=None
    w.bind("<Enter>", show, add="+")
    w.bind("<Leave>", hide, add="+")


class _PwPr(tk.Toplevel):
    def __init__(self, p, title, prompt, confirm=False):
        super().__init__(p); self.update_idletasks()
        self.title(title); self.configure(bg=_c("bg")); self.resizable(False,False)
        self.result=None
        tk.Label(self, text=prompt, bg=_c("bg"), fg=_c("fg2"), font=F(9),
                 padx=24, pady=(18,0), justify="left").pack(fill="x")
        self._e=_Ent(self, show="●"); self._e.pack(fill="x",padx=24,pady=(6,0),ipady=9)
        self._e2=None
        if confirm:
            tk.Label(self, text=T("confirm_pw"), bg=_c("bg"), fg=_c("fg2"),
                     font=F(9), padx=24, pady=(10,0)).pack(fill="x")
            self._e2=_Ent(self, show="●"); self._e2.pack(fill="x",padx=24,pady=(6,0),ipady=9)
        self._st=tk.Label(self, text="", bg=_c("bg"), fg=_c("acc"), font=F(8))
        self._st.pack(padx=24, anchor="w", pady=(4,0))
        foot=tk.Frame(self, bg=_c("bg"), padx=24, pady=14); foot.pack(fill="x")
        _Btn(foot, T("cancel"), self.destroy, py=8).pack(side="right", padx=(6,0))
        _ABt(foot, "OK", self._ok, py=8).pack(side="right")
        self._e.bind("<Return>", lambda ev: self._ok())
        self.bind("<Escape>", lambda ev: self.destroy())
        self._center(p); self.grab_set(); self._e.focus_set()

    def _ok(self):
        v=self._e.val()
        if not v: self._st.config(text=T("pw_req")); return
        if self._e2 and self._e2.val()!=v: self._st.config(text=T("no_match")); return
        self.result=v; self.destroy()

    def _center(self, p):
        self.update_idletasks(); w=360; h=210 if self._e2 else 165
        x=p.winfo_rootx()+(p.winfo_width()-w)//2
        y=p.winfo_rooty()+(p.winfo_height()-h)//2
        self.geometry(f"{w}x{max(h,165)}+{max(0,x)}+{max(0,y)}")


class LangScreen(tk.Frame):
    def __init__(self, p, on_done):
        super().__init__(p, bg=_c("bg")); self._cb=on_done; self._build()

    def _build(self):
        c=tk.Frame(self, bg=_c("bg")); c.place(relx=0.5,rely=0.46,anchor="center")
        ico=_icon(52)
        if ico: il=tk.Label(c,image=ico,bg=_c("bg")); il.image=ico; il.pack()
        tk.Label(c, text="NullPass", bg=_c("bg"), fg=_c("fg"),
                 font=F(22,b=True)).pack(pady=(12,4))
        tk.Label(c, text="Choose language  /  Выберите язык",
                 bg=_c("bg"), fg=_c("fg3"), font=F(10)).pack(pady=(0,28))
        for code,label,sub in [("en","English","Password manager"),
                                ("ru","Русский","Менеджер паролей")]:
            row=tk.Frame(c, bg=_c("card"),
                         highlightthickness=1, highlightbackground=_c("line2"),
                         cursor="hand2")
            row.pack(fill="x", pady=4)
            inn=tk.Frame(row, bg=_c("card"), padx=22, pady=16); inn.pack(fill="x")
            tk.Label(inn, text=label, bg=_c("card"), fg=_c("fg"), font=F(12,b=True)).pack(anchor="w")
            tk.Label(inn, text=sub,   bg=_c("card"), fg=_c("fg3"), font=F(9)).pack(anchor="w")
            def _pick(lc=code):
                global _LANG; _LANG=lc
                c2=_lcfg(); c2["lang"]=lc; _scfg(c2); self._cb()
            for wgt in (row, inn)+tuple(inn.winfo_children()):
                wgt.bind("<Button-1>", lambda ev,f=_pick: f())
                wgt.bind("<Enter>", lambda ev,r=row: r.config(bg=_c("hover")))
                wgt.bind("<Leave>", lambda ev,r=row: r.config(bg=_c("card")))


class UnlockScreen(tk.Frame):
    def __init__(self, p, vault, on_unlock):
        super().__init__(p, bg=_c("bg"))
        self.vault=vault; self._cb=on_unlock; self._vis=False; self._build()
        self.after(100, lambda: self._ep.focus_set())

    def _build(self):
        c=tk.Frame(self, bg=_c("bg")); c.place(relx=0.5,rely=0.46,anchor="center")
        ico=_icon(48)
        if ico: il=tk.Label(c,image=ico,bg=_c("bg")); il.image=ico; il.pack()
        is_new=not self.vault.exists()
        tk.Label(c, text="NullPass", bg=_c("bg"), fg=_c("fg"),
                 font=F(20,b=True)).pack(pady=(12,2))
        tk.Label(c, text=T("create_new") if is_new else T("welcome"),
                 bg=_c("bg"), fg=_c("fg3"), font=F(10)).pack()
        tk.Frame(c, bg=_c("bg"), height=20).pack()

        card=tk.Frame(c, bg=_c("card"),
                      highlightthickness=1, highlightbackground=_c("line2"),
                      padx=28, pady=22)
        card.pack(fill="x", ipadx=6)

        if is_new:
            wf=tk.Frame(card, bg="#110005", padx=12, pady=8,
                        highlightthickness=1, highlightbackground="#330010")
            wf.pack(fill="x", pady=(0,14))
            tk.Label(wf, text=T("pw_warning"), bg="#110005",
                     fg=_c("acc"), font=F(8), anchor="w").pack(anchor="w")

        tk.Label(card, text=T("master_pw"), bg=_c("card"), fg=_c("fg2"),
                 font=F(9), anchor="w").pack(fill="x", pady=(0,4))
        er=tk.Frame(card, bg=_c("card")); er.pack(fill="x")
        self._ep=_Ent(er, show="●"); self._ep.pack(side="left",fill="x",expand=True,ipady=10)
        eye=tk.Label(er, text="◎", bg=_c("btn"), fg=_c("fg3"),
                     cursor="hand2", font=F(12), padx=11, pady=10)
        eye.pack(side="left", padx=(3,0))
        def _tog():
            self._vis=not self._vis
            self._ep.config(show="" if self._vis else "●")
            eye.config(text="◉" if self._vis else "◎")
        eye.bind("<Button-1>", lambda ev: _tog())
        eye.bind("<Enter>", lambda ev: eye.config(fg=_c("fg"),bg=_c("btn_h")))
        eye.bind("<Leave>", lambda ev: eye.config(fg=_c("fg3"),bg=_c("btn")))

        self._ec=None
        if is_new:
            tk.Frame(card, bg=_c("card"), height=12).pack()
            tk.Label(card, text=T("confirm_pw"), bg=_c("card"), fg=_c("fg2"),
                     font=F(9), anchor="w").pack(fill="x", pady=(0,4))
            self._ec=_Ent(card, show="●"); self._ec.pack(fill="x",ipady=10)
            self._ec.bind("<Return>", lambda ev: self._submit())
            tk.Frame(card, bg=_c("card"), height=10).pack()
            self._sbar=_SBar(card, h=3); self._sbar.pack(fill="x")
            self._slbl=tk.Label(card, text="", bg=_c("card"), fg=_c("fg3"),
                                font=F(8), anchor="w")
            self._slbl.pack(fill="x", pady=(2,0))
            self._ep.bind("<KeyRelease>", self._ups)

        self._ep.bind("<Return>", lambda ev: self._submit())
        self._st=tk.Label(card, text="", bg=_c("card"), fg=_c("acc"), font=F(9))
        self._st.pack(pady=(12,0))

        if self.vault.fails >= self.vault.max_fail:
            self._st.config(text=T("too_many"))
        else:
            tk.Frame(card, bg=_c("card"), height=10).pack()
            _ABt(card, T("create_vault") if is_new else T("unlock"),
                 self._submit, py=12).pack(fill="x")

        tk.Frame(c, bg=_c("bg"), height=16).pack()
        tk.Label(c, text=T("enc_info"), bg=_c("bg"), fg=_c("fg3"), font=F(8)).pack()
        if not is_new:
            tk.Label(c, text=str(self.vault.path),
                     bg=_c("bg"), fg=_c("fg4"), font=F(7)).pack(pady=(2,0))

    def _ups(self, ev=None):
        pw=self._ep.get()
        if not pw: self._slbl.config(text=""); return
        sc,lb,col=pw_str(pw); bits=entropy(pw); self._sbar.refresh(pw)
        self._slbl.config(
            text=f"{lb}  ·  {bits} {T('bits')}  ·  {T('crack_time')}: {crack(bits)}",
            fg=col)

    def _submit(self):
        pw=self._ep.get()
        if not pw: self._st.config(text=T("pw_req")); return
        if not self.vault.exists():
            cf=self._ec.get() if self._ec else ""
            if len(pw)<8: self._st.config(text=T("min8")); return
            if pw!=cf:    self._st.config(text=T("no_match")); return
            self._st.config(text=T("creating"),fg=_c("fg3")); self.update()
            self.vault.create(pw); self._cb()
        else:
            self._st.config(text=T("unlocking"),fg=_c("fg3")); self.update()
            if self.vault.unlock(pw): self._cb()
            else:
                left=max(0, self.vault.max_fail-self.vault.fails)
                self._st.config(
                    text=f"{T('wrong_pw')} · {left} {T('attempts_left')}" if left else T("too_many"),
                    fg=_c("acc"))
                self._ep.delete(0,tk.END)


class EntryDlg(tk.Toplevel):
    def __init__(self, p, vault, entry=None):
        super().__init__(p); self.update_idletasks()
        self.vault=vault; self.entry=entry; self.result=None
        self.title(T("edit") if entry else T("new"))
        self.configure(bg=_c("bg")); self.resizable(True,True)
        self._vis=False; self._cf_rows=[]; self._build()
        if entry: self._fill(entry)
        self._center(p); self.grab_set(); self.focus_set()

    def _build(self):
        hdr=tk.Frame(self, bg=_c("bg2"), padx=20, pady=12); hdr.pack(fill="x")
        tk.Label(hdr, text=T("edit") if self.entry else T("new"),
                 bg=_c("bg2"), fg=_c("fg"), font=F(12,b=True)).pack(side="left")
        tk.Label(hdr, text="Ctrl+Return  ·  Esc",
                 bg=_c("bg2"), fg=_c("fg3"), font=F(8)).pack(side="right")

        sf=_SF(self, bg=_c("bg")); sf.pack(fill="both",expand=True); b=sf.inner

        def lbl(t, req=False):
            row=tk.Frame(b, bg=_c("bg")); row.pack(fill="x",padx=20,pady=(12,0))
            tk.Label(row, text=t, bg=_c("bg"), fg=_c("fg3"), font=F(8)).pack(side="left")
            if req: tk.Label(row, text=" *", bg=_c("bg"), fg=_c("acc"), font=F(8)).pack(side="left")

        def inp(ph="", show=""):
            e=_Ent(b, ph=ph, show=show)
            e.pack(fill="x", padx=20, pady=(4,0), ipady=9); return e

        lbl(T("title"), True);    self._ft=inp("Google, GitHub, Bank…")
        lbl(T("username"));       self._fu=inp("user@example.com")
        lbl(T("password"), True)

        pr=tk.Frame(b, bg=_c("bg")); pr.pack(fill="x",padx=20,pady=(4,0))
        self._fp=_Ent(pr, show="●"); self._fp.pack(side="left",fill="x",expand=True,ipady=9)

        def _tog():
            self._vis=not self._vis
            if not self._fp._ph_on: self._fp.config(show="" if self._vis else "●")

        def _gen():
            kw={k:v.get() for k,v in self._pvars.items()}
            kw["noamb"]=self._ambi.get(); kw["xsym"]=self._exsym.get()
            pw=mkpw(self._plen.get(), **kw)
            self._fp._ph_on=False; self._fp.delete(0,tk.END)
            self._fp.config(fg=_c("fg"),show=""); self._fp.insert(0,pw)
            self._vis=True; self._upd()

        def _phrase():
            slist=["-","."," ","_"][self._psep.get()]
            pw=mkphrase(w=self._pwc.get(), sep=slist,
                        cap=self._pcap.get(), num=self._pnum.get())
            self._fp._ph_on=False; self._fp.delete(0,tk.END)
            self._fp.config(fg=_c("fg"),show=""); self._fp.insert(0,pw)
            self._vis=True; self._upd()

        for txt,act in[(T("show"),_tog),(T("generate"),_gen),(T("passphrase"),_phrase)]:
            lb=tk.Label(pr, text=txt, bg=_c("btn"), fg=_c("btn_fg"),
                        font=F(8), padx=8, pady=9, cursor="hand2")
            lb.pack(side="left", padx=(3,0))
            lb.bind("<Button-1>", lambda ev,a=act: a())
            lb.bind("<Enter>", lambda ev,w=lb: w.config(fg=_c("fg"),bg=_c("btn_h")))
            lb.bind("<Leave>", lambda ev,w=lb: w.config(fg=_c("btn_fg"),bg=_c("btn")))

        self._sbar=_SBar(b,h=3); self._sbar.pack(fill="x",padx=20,pady=(6,0))
        self._slbl=tk.Label(b, text="", bg=_c("bg"), fg=_c("fg3"), font=F(8), anchor="w")
        self._slbl.pack(fill="x",padx=20,pady=(1,0))
        self._fp.bind("<KeyRelease>", lambda ev: self._upd())

        gf=tk.Frame(b, bg=_c("bg3"),
                    highlightthickness=1, highlightbackground=_c("line2"))
        gf.pack(fill="x",padx=20,pady=(6,0))
        gi=tk.Frame(gf, bg=_c("bg3"), padx=12, pady=8); gi.pack(fill="x")

        lr=tk.Frame(gi, bg=_c("bg3")); lr.pack(fill="x")
        tk.Label(lr, text=T("length"), bg=_c("bg3"), fg=_c("fg3"), font=F(8)).pack(side="left")
        self._plen=tk.IntVar(value=20)
        self._plen_l=tk.Label(lr, text="20", bg=_c("bg3"), fg=_c("acc"), font=F(8,b=True))
        self._plen_l.pack(side="right")
        tk.Scale(lr, from_=6, to=80, orient="horizontal", variable=self._plen,
                 bg=_c("bg3"), fg=_c("fg3"), troughcolor=_c("bg4"),
                 activebackground=_c("acc"), highlightthickness=0, bd=0, showvalue=False,
                 command=lambda v: self._plen_l.config(text=v)).pack(
                     side="left", fill="x", expand=True, padx=6)

        self._pvars={}
        cf2=tk.Frame(gi, bg=_c("bg3")); cf2.pack(fill="x",pady=(5,0))
        for i,(k,lb2,d) in enumerate([("up",T("uppercase"),True),("lo",T("lowercase"),True),
                                       ("dg",T("digits"),True),("sy",T("symbols"),True)]):
            v=tk.BooleanVar(value=d); self._pvars[k]=v
            tk.Checkbutton(cf2, text=lb2, variable=v,
                           bg=_c("bg3"), fg=_c("fg2"), selectcolor=_c("bg5"),
                           activebackground=_c("bg3"), font=F(9),
                           pady=2).grid(row=0,column=i,sticky="w",padx=3)

        op=tk.Frame(gi, bg=_c("bg3")); op.pack(fill="x",pady=(3,0))
        self._ambi=tk.BooleanVar(value=False); self._exsym=tk.BooleanVar(value=False)
        for txt2,var2 in[(T("no_ambiguous"),self._ambi),(T("extra_syms"),self._exsym)]:
            tk.Checkbutton(op, text=txt2, variable=var2,
                           bg=_c("bg3"), fg=_c("fg3"), selectcolor=_c("bg5"),
                           activebackground=_c("bg3"), font=F(8),
                           pady=2).pack(side="left",padx=3)

        pf=tk.Frame(gi, bg=_c("bg3")); pf.pack(fill="x",pady=(5,0))
        tk.Label(pf, text=T("phrase_words")+":", bg=_c("bg3"), fg=_c("fg3"), font=F(8)).pack(side="left")
        self._pwc=tk.IntVar(value=4); self._psep=tk.IntVar(value=0)
        self._pcap=tk.BooleanVar(value=False); self._pnum=tk.BooleanVar(value=True)
        tk.Spinbox(pf, from_=3, to=8, textvariable=self._pwc, width=3,
                   bg=_c("bg4"), fg=_c("fg2"), buttonbackground=_c("bg5"),
                   relief="flat", font=F(9)).pack(side="left",padx=(6,4))
        for t2,v2 in [(T("cap"),self._pcap),(T("num"),self._pnum)]:
            tk.Checkbutton(pf, text=t2, variable=v2,
                           bg=_c("bg3"), fg=_c("fg3"), selectcolor=_c("bg5"),
                           activebackground=_c("bg3"), font=F(8)).pack(side="left",padx=2)
        tk.Label(pf, text="  sep:", bg=_c("bg3"), fg=_c("fg3"), font=F(8)).pack(side="left")
        for i2,s2 in enumerate(["-","."," ","_"]):
            tk.Radiobutton(pf, text=repr(s2) if s2==" " else s2,
                           variable=self._psep, value=i2,
                           bg=_c("bg3"), fg=_c("fg3"), selectcolor=_c("bg5"),
                           activebackground=_c("bg3"), font=F(9)).pack(side="left",padx=1)

        lbl("URL"); self._furl=inp("https://example.com")
        lbl(T("category"))
        self._fcat=_Ent(b, ph="General"); self._fcat.pack(fill="x",padx=20,pady=(4,0),ipady=9)
        pills=tk.Frame(b, bg=_c("bg")); pills.pack(fill="x",padx=20,pady=(4,0))
        for cat in CATS:
            p2=tk.Label(pills, text=cat, bg=_c("btn"), fg=_c("btn_fg"),
                        font=F(8), padx=6, pady=2, cursor="hand2")
            p2.pack(side="left",padx=(0,3),pady=(0,2))
            p2.bind("<Button-1>", lambda ev,c=cat: self._fcat.set_val(c))
            p2.bind("<Enter>", lambda ev,w=p2: w.config(fg=_c("fg"),bg=_c("btn_h")))
            p2.bind("<Leave>", lambda ev,w=p2: w.config(fg=_c("btn_fg"),bg=_c("btn")))

        lbl(T("tags"));  self._ftags=inp("personal, work")
        lbl(T("totp"))
        tr2=tk.Frame(b, bg=_c("bg")); tr2.pack(fill="x",padx=20,pady=(4,0))
        self._ftotp=_Ent(tr2, ph="JBSWY3DPEHPK3PXP")
        self._ftotp.pack(side="left",fill="x",expand=True,ipady=9)
        tb=tk.Label(tr2, text=T("test"), bg=_c("btn"), fg=_c("btn_fg"),
                    font=F(8), padx=8, pady=9, cursor="hand2")
        tb.pack(side="left",padx=(3,0))
        def _ttest():
            s=self._ftotp.val().strip()
            if not s: return
            try:
                code,rem=do_totp(s)
                messagebox.showinfo(T("test"),T("totp_ok",code=code,rem=rem),parent=self)
            except Exception as ex:
                messagebox.showerror(T("totp_err"),str(ex),parent=self)
        tb.bind("<Button-1>", lambda ev: _ttest())
        tb.bind("<Enter>", lambda ev: tb.config(fg=_c("fg"),bg=_c("btn_h")))
        tb.bind("<Leave>", lambda ev: tb.config(fg=_c("btn_fg"),bg=_c("btn")))

        lbl(T("notes"))
        self._fnotes=tk.Text(b, bg=_c("inp"), fg=_c("fg"), insertbackground=_c("fg"),
                             relief="flat", font=F(10),
                             highlightthickness=1, highlightbackground=_c("inp_b"),
                             height=4, width=1)
        self._fnotes.pack(fill="x",padx=20,pady=(4,0),ipady=4)

        _div(b, px=20, py=(12,0))
        cfh=tk.Frame(b, bg=_c("bg")); cfh.pack(fill="x",padx=20,pady=(8,0))
        tk.Label(cfh, text=T("custom_fields"), bg=_c("bg"), fg=_c("fg3"),
                 font=F(8)).pack(side="left")
        adf=tk.Label(cfh, text=T("add_field"), bg=_c("bg"), fg=_c("acc"),
                     font=F(8), cursor="hand2")
        adf.pack(side="right")
        adf.bind("<Button-1>", lambda ev: self._add_cf())
        self._cf_frame=tk.Frame(b, bg=_c("bg")); self._cf_frame.pack(fill="x",padx=20,pady=(4,0))

        if self.entry and self.entry.get("history"):
            _div(b, px=20, py=(12,4))
            tk.Label(b, text=T("pw_history"), bg=_c("bg"), fg=_c("fg3"),
                     font=F(8), anchor="w").pack(fill="x",padx=20,pady=(4,4))
            hw=tk.Frame(b, bg=_c("card"),
                        highlightthickness=1, highlightbackground=_c("line"))
            hw.pack(fill="x",padx=20,pady=(0,4))
            for h in reversed(self.entry["history"][-5:]):
                row=tk.Frame(hw, bg=_c("card")); row.pack(fill="x")
                tk.Label(row, text="●"*min(len(h.get("pw","")),28),
                         bg=_c("card"), fg=_c("fg3"),
                         font=F(9,m=True), padx=12, pady=6).pack(side="left")
                def _res(pw=h.get("pw","")):
                    self._fp._ph_on=False; self._fp.delete(0,tk.END)
                    self._fp.config(fg=_c("fg"),show="" if self._vis else "●")
                    self._fp.insert(0,pw); self._upd()
                rb=tk.Label(row, text=T("restore_pw"), bg=_c("card"),
                            fg=_c("fg3"), font=F(8), padx=8, cursor="hand2")
                rb.pack(side="right")
                rb.bind("<Button-1>", lambda ev,f=_res: f())
                rb.bind("<Enter>", lambda ev,w=rb: w.config(fg=_c("acc")))
                rb.bind("<Leave>", lambda ev,w=rb: w.config(fg=_c("fg3")))
                tk.Label(row, text=_fmt(h.get("when","")),
                         bg=_c("card"), fg=_c("fg3"),
                         font=F(8), padx=10).pack(side="right")

        tk.Frame(b, bg=_c("bg"), height=12).pack()
        _div(self)
        foot=tk.Frame(self, bg=_c("bg2"), padx=18, pady=10); foot.pack(fill="x")
        _Btn(foot, T("cancel"), self.destroy, py=8).pack(side="right",padx=(6,0))
        _ABt(foot, T("save"), self._save, py=8).pack(side="right")
        self.bind("<Escape>", lambda ev: self.destroy())
        self.bind("<Control-Return>", lambda ev: self._save())

    def _add_cf(self, label="", value="", secret=False):
        row=tk.Frame(self._cf_frame, bg=_c("bg3"),
                     highlightthickness=1, highlightbackground=_c("line2"))
        row.pack(fill="x",pady=2)
        inn=tk.Frame(row, bg=_c("bg3"), padx=6, pady=5); inn.pack(fill="x")
        lv=tk.StringVar(value=label); vv=tk.StringVar(value=value)
        sv=tk.BooleanVar(value=secret)
        le=tk.Entry(inn, textvariable=lv, bg=_c("inp"), fg=_c("fg"),
                    insertbackground=_c("fg"), relief="flat", font=F(9),
                    width=12, highlightthickness=1, highlightbackground=_c("inp_b"))
        le.pack(side="left",padx=(0,4),ipady=4)
        ve=tk.Entry(inn, textvariable=vv, bg=_c("inp"), fg=_c("fg"),
                    insertbackground=_c("fg"), relief="flat", font=F(9),
                    highlightthickness=1, highlightbackground=_c("inp_b"))
        ve.pack(side="left",fill="x",expand=True,ipady=4)
        tk.Checkbutton(inn, text="secret", variable=sv,
                       bg=_c("bg3"), fg=_c("fg3"), selectcolor=_c("bg5"),
                       activebackground=_c("bg3"), font=F(8)).pack(side="left",padx=4)
        rm=tk.Label(inn, text="✕", bg=_c("bg3"), fg=_c("fg3"),
                    font=F(9), cursor="hand2", padx=4)
        rm.pack(side="right")
        rm.bind("<Button-1>", lambda ev,r=row: self._rm_cf(r))
        rm.bind("<Enter>", lambda ev: rm.config(fg=_c("acc")))
        rm.bind("<Leave>", lambda ev: rm.config(fg=_c("fg3")))
        self._cf_rows.append((row,lv,vv,sv))

    def _rm_cf(self, row):
        self._cf_rows=[r for r in self._cf_rows if r[0]!=row]; row.destroy()

    def _upd(self):
        pw=self._fp.get()
        if self._fp._ph_on or not pw: self._slbl.config(text=""); return
        sc,lb,col=pw_str(pw); bits=entropy(pw); self._sbar.refresh(pw)
        self._slbl.config(
            text=f"{lb}  ·  {bits} {T('bits')}  ·  {T('crack_time')}: {crack(bits)}",
            fg=col)

    def _fill(self, e):
        for fld,k in[(self._ft,"title"),(self._fu,"username"),
                     (self._furl,"url"),(self._fcat,"category")]:
            v=e.get(k,"")
            if v: fld.set_val(v)
        pw=e.get("password",""); self._fp._ph_on=False; self._fp.delete(0,tk.END)
        self._fp.config(fg=_c("fg"),show="●"); self._fp.insert(0,pw)
        if e.get("tags"):   self._ftags.set_val(", ".join(e["tags"]))
        if e.get("totp"):   self._ftotp.set_val(e["totp"])
        if e.get("notes"):  self._fnotes.insert("1.0",e["notes"])
        for cf in e.get("custom_fields",[]):
            self._add_cf(cf.get("label",""),cf.get("value",""),cf.get("secret",False))
        self._upd()

    def _save(self):
        t=self._ft.val().strip(); pw=self._fp.get() if not self._fp._ph_on else ""
        if not t:  messagebox.showwarning("",T("title_req"),parent=self); return
        if not pw: messagebox.showwarning("",T("pw_req"),  parent=self); return
        raw=self._ftags.val().strip()
        tags=[x.strip() for x in raw.split(",") if x.strip()] if raw else []
        cfs=[]
        for _,lv,vv,sv in self._cf_rows:
            l=lv.get().strip()
            if l: cfs.append({"label":l,"value":vv.get(),"secret":sv.get()})
        self.result={"title":t,"username":self._fu.val(),"password":pw,
                     "url":self._furl.val(),"category":self._fcat.val() or "General",
                     "tags":tags,"totp":self._ftotp.val(),
                     "notes":self._fnotes.get("1.0",tk.END).strip(),
                     "custom_fields":cfs}
        self.destroy()

    def _center(self, p):
        self.update_idletasks(); w,h=580,840
        x=p.winfo_rootx()+(p.winfo_width()-w)//2
        y=p.winfo_rooty()+(p.winfo_height()-h)//2
        self.geometry(f"{w}x{h}+{max(0,x)}+{max(0,y)}")


class AuditDlg(tk.Toplevel):
    def __init__(self, p, vault):
        super().__init__(p); self.update_idletasks()
        self.title(T("audit_title"))
        self.configure(bg=_c("bg")); self.resizable(True,True); self._v=vault
        self._build(); self._center(p); self.grab_set()

    def _build(self):
        hdr=tk.Frame(self, bg=_c("bg2"), padx=20, pady=12); hdr.pack(fill="x")
        tk.Label(hdr, text=T("audit_title"), bg=_c("bg2"), fg=_c("fg"),
                 font=F(12,b=True)).pack(side="left")
        sf=_SF(self, bg=_c("bg")); sf.pack(fill="both",expand=True); b=sf.inner
        st=self._v.stats(); tk.Frame(b, bg=_c("bg"), height=14).pack()

        total=st["total"] or 1
        issues=st["dupes"]+st["weak"]+st["old"]
        score=max(0, 100-int(issues/total*100))
        sc=_c("green") if score>=80 else _c("amber") if score>=50 else _c("acc")
        sl=T("excellent") if score>=80 else T("fair") if score>=50 else T("poor")

        cf2=tk.Frame(b, bg=_c("bg")); cf2.pack(pady=(0,8))
        cv=tk.Canvas(cf2, width=120, height=120, bg=_c("bg"), highlightthickness=0); cv.pack()
        cv.create_oval(10,10,110,110, outline=_c("line2"), width=10)
        ext=int(score*3.6)
        if ext>0:
            cv.create_arc(10,10,110,110, start=90, extent=-ext,
                          outline=sc, width=10, style="arc")
        cv.create_text(60,50, text=str(score), fill=sc, font=F(26,b=True))
        cv.create_text(60,74, text=sl, fill=_c("fg3"), font=F(9))

        g=tk.Frame(b, bg=_c("bg"), padx=16); g.pack(fill="x")
        for i in range(3): g.columnconfigure(i, weight=1)

        def card(row, col, lbl, val, cv2, note=""):
            f=tk.Frame(g, bg=_c("card"),
                       highlightthickness=1, highlightbackground=_c("line"))
            f.grid(row=row, column=col, sticky="ew", padx=3, pady=3)
            inn=tk.Frame(f, bg=_c("card"), padx=12, pady=10); inn.pack(fill="x")
            tk.Label(inn, text=lbl, bg=_c("card"), fg=_c("fg3"), font=F(8)).pack(anchor="w")
            tk.Label(inn, text=str(val), bg=_c("card"), fg=cv2,
                     font=F(18,b=True)).pack(anchor="w")
            if note: tk.Label(inn, text=note, bg=_c("card"), fg=_c("fg3"),
                              font=F(7)).pack(anchor="w")

        card(0,0,T("total"),     st["total"],   _c("fg"))
        card(0,1,T("starred"),   st["fav"],     _c("amber"))
        card(0,2,"2FA",          st["with_2fa"],_c("green") if st["with_2fa"] else _c("fg3"))
        card(1,0,T("duplicates"),st["dupes"],   _c("acc") if st["dupes"] else _c("green"),T("same_pw"))
        card(1,1,T("weak"),      st["weak"],    _c("acc") if st["weak"]  else _c("green"))
        card(1,2,T("outdated"),  st["old"],     _c("amber") if st["old"] else _c("green"),T("days_old"))

        wl=[e for e in self._v.entries if pw_str(e.get("password",""))[0]<50]
        if wl:
            tk.Frame(b, bg=_c("bg"), height=10).pack()
            tk.Label(b, text=T("weak_pws"), bg=_c("bg"), fg=_c("fg2"),
                     font=F(9,b=True), anchor="w").pack(fill="x",padx=16,pady=(0,4))
            for e in wl[:8]:
                sc2,lb2,col2=pw_str(e.get("password",""))
                r=tk.Frame(b, bg=_c("card"),
                           highlightthickness=1, highlightbackground=_c("line"))
                r.pack(fill="x",padx=16,pady=2)
                inn=tk.Frame(r, bg=_c("card"), padx=12, pady=8); inn.pack(fill="x")
                tk.Label(inn, text=e["title"], bg=_c("card"), fg=_c("fg"),
                         font=F(10)).pack(side="left")
                bits=entropy(e.get("password",""))
                tk.Label(inn, text=f"{lb2}  ·  {bits}b  ·  {crack(bits)}",
                         bg=_c("card"), fg=col2, font=F(8)).pack(side="right")

        pc=Counter(e["password"] for e in self._v.entries if e.get("password"))
        dpw={p for p,n in pc.items() if n>1}
        de=[e for e in self._v.entries if e.get("password") in dpw]
        if de:
            tk.Frame(b, bg=_c("bg"), height=8).pack()
            tk.Label(b, text=T("dup_pws"), bg=_c("bg"), fg=_c("fg2"),
                     font=F(9,b=True), anchor="w").pack(fill="x",padx=16,pady=(0,4))
            seen={}
            for e in de: seen.setdefault(e.get("password",""),[]).append(e["title"])
            for pw,titles in list(seen.items())[:5]:
                r=tk.Frame(b, bg=_c("card"),
                           highlightthickness=1, highlightbackground=_c("acc"))
                r.pack(fill="x",padx=16,pady=2)
                inn=tk.Frame(r, bg=_c("card"), padx=12, pady=8); inn.pack(fill="x")
                tk.Label(inn, text="  ·  ".join(titles[:3]),
                         bg=_c("card"), fg=_c("fg"), font=F(9)).pack(side="left")
                tk.Label(inn, text=T("same_pw"),
                         bg=_c("card"), fg=_c("acc"), font=F(8)).pack(side="right")

        tk.Frame(b, bg=_c("bg"), height=10).pack()
        bf=tk.Frame(b, bg=_c("card"),
                    highlightthickness=1, highlightbackground=_c("line"))
        bf.pack(fill="x",padx=16,pady=(0,8))
        bi=tk.Frame(bf, bg=_c("card"), padx=12, pady=12); bi.pack(fill="x")
        tk.Label(bi, text=T("hibp"), bg=_c("card"), fg=_c("fg"),
                 font=F(10,b=True)).pack(anchor="w")
        tk.Label(bi, text=T("hibp_info"), bg=_c("card"), fg=_c("fg3"),
                 font=F(8), wraplength=440, justify="left").pack(anchor="w",pady=(2,8))
        self._bl=tk.Label(bi, text="", bg=_c("card"), fg=_c("fg3"),
                          font=F(8), anchor="w", wraplength=440, justify="left")
        self._bl.pack(anchor="w")
        self._bp=tk.Label(bi, text="", bg=_c("card"), fg=_c("fg3"),
                          font=F(8), anchor="w")
        self._bp.pack(anchor="w")
        _ABt(bi, T("hibp_check"), self._run, py=7).pack(anchor="w",pady=(10,0))

        tk.Frame(b, bg=_c("bg"), height=12).pack()
        _div(self)
        foot=tk.Frame(self, bg=_c("bg2"), padx=18, pady=10); foot.pack(fill="x")
        _ABt(foot, T("close"), self.destroy, py=8).pack(side="right")

    def _run(self):
        self._bl.config(text="",fg=_c("fg3")); self._bp.config(text="…")
        entries=[e for e in self._v.entries if e.get("password")]
        total=len(entries); results=[]
        def worker():
            for i,e in enumerate(entries):
                self.after(0, lambda i=i: self._bp.config(
                    text=T("hibp_progress",i=i+1,n=total)))
                cnt=check_breach(e["password"])
                if cnt is None: results.append((e["title"],None))
                elif cnt>0:     results.append((e["title"],cnt))
            self.after(0, lambda: self._show(results,total))
        threading.Thread(target=worker, daemon=True).start()

    def _show(self, results, total):
        self._bp.config(text="")
        found=[(t,c) for t,c in results if c is not None]
        if not found:
            self._bl.config(text="✓  "+T("hibp_ok",n=total), fg=_c("green"))
        else:
            self._bl.config(
                text="\n".join("⚠  "+T("hibp_found",t=t,n=c) for t,c in found[:10]),
                fg=_c("acc"))

    def _center(self, p):
        w,h=520,700
        x=p.winfo_rootx()+(p.winfo_width()-w)//2
        y=p.winfo_rooty()+(p.winfo_height()-h)//2
        self.geometry(f"{w}x{h}+{max(0,x)}+{max(0,y)}")


class TrashDlg(tk.Toplevel):
    def __init__(self, p, vault):
        super().__init__(p); self.update_idletasks()
        self.title(T("trash_title"))
        self.configure(bg=_c("bg")); self.resizable(True,True)
        self._v=vault; self._p=p
        self._build(); self._center(p); self.grab_set()

    def _build(self):
        hdr=tk.Frame(self, bg=_c("bg2"), padx=20, pady=12); hdr.pack(fill="x")
        tk.Label(hdr, text=T("trash_title"), bg=_c("bg2"), fg=_c("fg"),
                 font=F(12,b=True)).pack(side="left")
        tk.Label(hdr, text=str(len(self._v._trash)),
                 bg=_c("bg2"), fg=_c("fg3"), font=F(9)).pack(side="left",padx=(8,0))
        sf=_SF(self, bg=_c("bg")); sf.pack(fill="both",expand=True); b=sf.inner
        tk.Frame(b, bg=_c("bg"), height=8).pack()

        if not self._v._trash:
            tk.Label(b, text=T("trash_empty"), bg=_c("bg"), fg=_c("fg3"),
                     font=F(11)).pack(pady=40)
        else:
            for e in reversed(self._v._trash):
                r=tk.Frame(b, bg=_c("card"),
                           highlightthickness=1, highlightbackground=_c("line"))
                r.pack(fill="x",padx=16,pady=3)
                inn=tk.Frame(r, bg=_c("card"), padx=12, pady=10); inn.pack(fill="x")
                left=tk.Frame(inn, bg=_c("card")); left.pack(side="left",fill="x",expand=True)
                tk.Label(left, text=e["title"], bg=_c("card"), fg=_c("fg"),
                         font=F(10,b=True)).pack(anchor="w")
                tk.Label(left,
                         text=f"{e.get('category','General')}  ·  {_fmt(e.get('deleted_at',''))}",
                         bg=_c("card"), fg=_c("fg3"), font=F(8)).pack(anchor="w")
                def _res(eid=e["id"]):
                    self._v.restore(eid)
                    if hasattr(self._p,"_build_cats"):
                        self._p._build_cats(); self._p._refresh()
                    self.destroy(); TrashDlg(self._p, self._v)
                rb=tk.Label(inn, text=T("restore"), bg=_c("card"),
                            fg=_c("fg3"), font=F(9), cursor="hand2", padx=8)
                rb.pack(side="right")
                rb.bind("<Button-1>", lambda ev,f=_res: f())
                rb.bind("<Enter>", lambda ev,w=rb: w.config(fg=_c("acc")))
                rb.bind("<Leave>", lambda ev,w=rb: w.config(fg=_c("fg3")))

        tk.Frame(b, bg=_c("bg"), height=8).pack()
        _div(self)
        foot=tk.Frame(self, bg=_c("bg2"), padx=18, pady=10); foot.pack(fill="x")
        _ABt(foot, T("close"), self.destroy, py=8).pack(side="right")
        if self._v._trash:
            _ABt(foot, T("empty_trash"), self._empty, py=8, danger=True).pack(side="left")

    def _empty(self):
        if not messagebox.askyesno("",T("empty_confirm"),parent=self): return
        self._v.empty_trash(); self.destroy()

    def _center(self, p):
        w,h=460,520
        x=p.winfo_rootx()+(p.winfo_width()-w)//2
        y=p.winfo_rooty()+(p.winfo_height()-h)//2
        self.geometry(f"{w}x{h}+{max(0,x)}+{max(0,y)}")


class SettingsDlg(tk.Toplevel):
    def __init__(self, p, vault):
        super().__init__(p); self.update_idletasks()
        self.title(T("settings_title"))
        self.configure(bg=_c("bg")); self.resizable(False,False)
        self._v=vault; self._p=p
        self._build(); self._center(p); self.grab_set(); self.focus_set()

    def _build(self):
        hdr=tk.Frame(self, bg=_c("bg2"), padx=20, pady=12); hdr.pack(fill="x")
        tk.Label(hdr, text=T("settings_title"), bg=_c("bg2"), fg=_c("fg"),
                 font=F(12,b=True)).pack(side="left")
        sf=_SF(self, bg=_c("bg")); sf.pack(fill="both",expand=True); b=sf.inner
        cfg=_lcfg()

        def sec(t):
            tk.Frame(b, bg=_c("bg"), height=14).pack()
            tk.Label(b, text=t.upper(), bg=_c("bg"), fg=_c("fg3"),
                     font=F(8,b=True), anchor="w").pack(fill="x",padx=20)
            tk.Frame(b, bg=_c("line"), height=1).pack(fill="x",padx=20,pady=(3,0))

        def card():
            f=tk.Frame(b, bg=_c("card"),
                       highlightthickness=1, highlightbackground=_c("line"))
            f.pack(fill="x",padx=20,pady=(7,0))
            inn=tk.Frame(f, bg=_c("card"), padx=14, pady=13); inn.pack(fill="x")
            return inn

        def row_lbl(p2, t, sub=None):
            tk.Label(p2, text=t, bg=_c("card"), fg=_c("fg"),
                     font=F(10,b=True)).pack(anchor="w")
            if sub: tk.Label(p2, text=sub, bg=_c("card"), fg=_c("fg3"),
                             font=F(8)).pack(anchor="w",pady=(1,0))

        sec(T("appearance"))
        ai=card(); row_lbl(ai, T("theme"))
        self._tv=tk.StringVar(value=cfg.get("theme","dark"))
        tr_row=tk.Frame(ai, bg=_c("card")); tr_row.pack(fill="x",pady=(8,0))
        for val,lbl2 in [("dark",T("dark")),("light",T("light"))]:
            tk.Radiobutton(tr_row, text=lbl2, variable=self._tv, value=val,
                           bg=_c("card"), fg=_c("fg3"), selectcolor=_c("bg5"),
                           activebackground=_c("card"), activeforeground=_c("fg"),
                           font=F(10), padx=8).pack(side="left")

        sec(T("lang"))
        li2=card(); row_lbl(li2, T("lang"), T("restart_note"))
        self._lv=tk.StringVar(value=cfg.get("lang","en"))
        lr_row=tk.Frame(li2, bg=_c("card")); lr_row.pack(fill="x",pady=(8,0))
        for val,lbl2 in [("en","English"),("ru","Русский")]:
            tk.Radiobutton(lr_row, text=lbl2, variable=self._lv, value=val,
                           bg=_c("card"), fg=_c("fg3"), selectcolor=_c("bg5"),
                           activebackground=_c("card"), activeforeground=_c("fg"),
                           font=F(10), padx=8).pack(side="left")

        sec(T("security"))
        li=card(); row_lbl(li, T("autolock"))
        self._lock_v=tk.StringVar(value=cfg.get("lock_after","5m"))
        lrow=tk.Frame(li, bg=_c("card")); lrow.pack(fill="x",pady=(8,0))
        for opt in LOCK_T:
            tk.Radiobutton(lrow, text=opt, variable=self._lock_v, value=opt,
                           bg=_c("card"), fg=_c("fg3"), selectcolor=_c("bg5"),
                           activebackground=_c("card"), activeforeground=_c("fg"),
                           font=F(9), padx=3).pack(side="left")

        ci=card(); row_lbl(ci, T("clip_clear"))
        self._clip_v=tk.StringVar(value=cfg.get("clip_after","30s"))
        crow=tk.Frame(ci, bg=_c("card")); crow.pack(fill="x",pady=(8,0))
        for opt in CLIP_T:
            tk.Radiobutton(crow, text=opt, variable=self._clip_v, value=opt,
                           bg=_c("card"), fg=_c("fg3"), selectcolor=_c("bg5"),
                           activebackground=_c("card"), activeforeground=_c("fg"),
                           font=F(9), padx=3).pack(side="left")

        mfi=card(); row_lbl(mfi, T("max_fail_lbl"))
        self._mf=tk.IntVar(value=cfg.get("max_fail",5))
        mrow=tk.Frame(mfi, bg=_c("card")); mrow.pack(fill="x",pady=(8,0))
        for n in [3,5,10,0]:
            tk.Radiobutton(mrow, text=T("unlimited") if n==0 else str(n),
                           variable=self._mf, value=n,
                           bg=_c("card"), fg=_c("fg3"), selectcolor=_c("bg5"),
                           activebackground=_c("card"), activeforeground=_c("fg"),
                           font=F(9), padx=3).pack(side="left")

        ei=card(); row_lbl(ei, T("encryption"))
        enc="Argon2id" if HAS_A2 else "PBKDF2-SHA256 (600k)"
        for line in [f"AES-256-GCM  +  {enc}",
                     "256-bit key  ·  256-bit salt  ·  HMAC-GCM auth"]:
            tk.Label(ei, text=line, bg=_c("card"), fg=_c("fg3"),
                     font=F(8,m=True), anchor="w").pack(fill="x",pady=2)

        sec(T("change_master"))
        pi=card()
        for attr,lbl3 in [("_op",T("current_pw")),
                          ("_np",T("new_pw")),
                          ("_np2",T("confirm_new"))]:
            tk.Label(pi, text=lbl3, bg=_c("card"), fg=_c("fg3"),
                     font=F(8), anchor="w").pack(fill="x")
            e=_Ent(pi, show="●"); e.pack(fill="x",pady=(3,10),ipady=8); setattr(self,attr,e)
        self._np_bar=_SBar(pi, h=3); self._np_bar.pack(fill="x")
        self._np_lbl=tk.Label(pi, text="", bg=_c("card"), fg=_c("fg3"),
                              font=F(8), anchor="w")
        self._np_lbl.pack(fill="x",pady=(2,8))
        self._np.bind("<KeyRelease>", self._upd_pw)
        self._ps=tk.Label(pi, text="", bg=_c("card"), fg=_c("acc"), font=F(9))
        self._ps.pack(anchor="w")
        tk.Frame(pi, bg=_c("card"), height=4).pack()
        _ABt(pi, T("change"), self._chpw, py=9).pack(fill="x")

        sec(T("data"))
        di=card(); row_lbl(di, T("export"))
        er=tk.Frame(di, bg=_c("card")); er.pack(fill="x",pady=(6,0))
        _Btn(er, T("exp_csv"), self._exp_csv, py=7).pack(side="left")
        _Btn(er, T("exp_enc"), self._exp_enc, py=7).pack(side="left",padx=(6,0))
        tk.Frame(di, bg=_c("card"), height=10).pack()
        row_lbl(di, T("import_"))
        ir=tk.Frame(di, bg=_c("card")); ir.pack(fill="x",pady=(6,0))
        _Btn(ir, T("imp_csv"), self._imp_csv, py=7).pack(side="left")
        _Btn(ir, T("imp_enc"), self._imp_enc, py=7).pack(side="left",padx=(6,0))
        self._ds=tk.Label(di, text="", bg=_c("card"), fg=_c("green"), font=F(9))
        self._ds.pack(anchor="w",pady=(8,0))

        sec(T("backup"))
        bi=card()
        bkups=self._v.list_backups()
        if bkups:
            tk.Label(bi, text=T("bk_found",n=len(bkups),name=bkups[0].name),
                     bg=_c("card"), fg=_c("fg3"), font=F(8,m=True)).pack(anchor="w",pady=(0,6))
        self._bk_lbl=tk.Label(bi, text="", bg=_c("card"), fg=_c("green"), font=F(8))
        self._bk_lbl.pack(anchor="w")
        br=tk.Frame(bi, bg=_c("card")); br.pack(fill="x",pady=(8,0))
        _Btn(br, T("create_bk"),   self._do_bk,       py=7).pack(side="left")
        _Btn(br, T("open_folder"), self._open_folder,  py=7).pack(side="left",padx=(6,0))

        sec(T("vault_file"))
        vi=card()
        tk.Label(vi, text=str(self._v.path), bg=_c("card"), fg=_c("fg3"),
                 font=F(8,m=True), wraplength=380, anchor="w").pack(anchor="w")

        sec(T("about"))
        ab=card()
        lr2=tk.Frame(ab, bg=_c("card")); lr2.pack(fill="x")
        ico=_icon(38)
        if ico: il=tk.Label(lr2,image=ico,bg=_c("card")); il.image=ico; il.pack(side="left")
        tb=tk.Frame(lr2, bg=_c("card")); tb.pack(side="left",padx=(12,0))
        tk.Label(tb, text="NullPass", bg=_c("card"), fg=_c("fg"),
                 font=F(13,b=True), anchor="w").pack(anchor="w")
        tk.Label(tb, text=f"v{VER}  ·  MIT License  ·  Local only",
                 bg=_c("card"), fg=_c("fg3"), font=F(9), anchor="w").pack(anchor="w")
        tk.Frame(ab, bg=_c("card"), height=8).pack()
        gl=tk.Label(ab, text=GITHUB, bg=_c("card"), fg=_c("acc"),
                    font=F(9), cursor="hand2", anchor="w")
        gl.pack(fill="x")
        gl.bind("<Button-1>", lambda ev: webbrowser.open(GITHUB))
        gl.bind("<Enter>", lambda ev: gl.config(fg=_c("fg")))
        gl.bind("<Leave>", lambda ev: gl.config(fg=_c("acc")))
        tk.Frame(ab, bg=_c("card"), height=4).pack()
        enc2="Argon2id" if HAS_A2 else "PBKDF2-SHA256"
        tk.Label(ab, text=f"AES-256-GCM · {enc2} · Python {sys.version[:6]}",
                 bg=_c("card"), fg=_c("fg4"), font=F(7), anchor="w").pack(anchor="w")

        tk.Frame(b, bg=_c("bg"), height=16).pack()
        _div(self)
        foot=tk.Frame(self, bg=_c("bg2"), padx=18, pady=10); foot.pack(fill="x")
        _Btn(foot, T("cancel"), self.destroy, py=8).pack(side="right",padx=(6,0))
        _ABt(foot, T("save"), self._save_cfg, py=8).pack(side="right")

    def _upd_pw(self, ev=None):
        pw=self._np.get()
        if not pw: self._np_lbl.config(text=""); return
        sc,lb,col=pw_str(pw); bits=entropy(pw); self._np_bar.refresh(pw)
        self._np_lbl.config(text=f"{lb}  ·  {bits} {T('bits')}  ·  {crack(bits)}",fg=col)

    def _save_cfg(self):
        cfg=_lcfg()
        cfg["lock_after"]=self._lock_v.get(); cfg["clip_after"]=self._clip_v.get()
        cfg["max_fail"]=self._mf.get(); cfg["theme"]=self._tv.get(); cfg["lang"]=self._lv.get()
        _scfg(cfg); self._v._reload()
        needs_restart=(cfg["theme"]!=_THEME_NAME or cfg["lang"]!=_LANG)
        self.destroy()
        if needs_restart:
            if messagebox.askyesno("",T("restart_req"),parent=self._p): _restart()

    def _chpw(self):
        old=self._op.get(); new=self._np.get(); new2=self._np2.get()
        if not old:    self._ps.config(text=T("pw_req"));   return
        if not new:    self._ps.config(text=T("pw_req"));   return
        if len(new)<8: self._ps.config(text=T("min8"));     return
        if new!=new2:  self._ps.config(text=T("no_match")); return
        self._ps.config(text="…",fg=_c("fg3")); self.update()
        if self._v.change_pw(old,new):
            for e in (self._op,self._np,self._np2): e.delete(0,tk.END)
            self._ps.config(text=T("pw_ok"),fg=_c("green"))
        else: self._ps.config(text=T("wrong_pw"),fg=_c("acc"))

    def _exp_csv(self):
        p=filedialog.asksaveasfilename(parent=self,defaultextension=".csv",
                                        filetypes=[("CSV","*.csv"),("All","*.*")])
        if not p: return
        try: self._v.export_csv(p); self._ds.config(text=T("exported",n=len(self._v.entries)),fg=_c("green"))
        except Exception as ex: self._ds.config(text=str(ex),fg=_c("acc"))

    def _exp_enc(self):
        p=filedialog.asksaveasfilename(parent=self,defaultextension=".npx",
                                        filetypes=[("NullPass Encrypted","*.npx"),("All","*.*")])
        if not p: return
        dlg=_PwPr(self,"",T("exp_pw"),confirm=True); self.wait_window(dlg)
        if not dlg.result: return
        try:
            self._v.export_enc(p,dlg.result)
            self._ds.config(text=T("exported",n=len(self._v.entries))+" (enc)",fg=_c("green"))
        except Exception as ex: self._ds.config(text=str(ex),fg=_c("acc"))

    def _imp_csv(self):
        p=filedialog.askopenfilename(parent=self,filetypes=[("CSV","*.csv"),("All","*.*")])
        if not p: return
        try: n=self._v.import_csv(p); self._ds.config(text=T("imported",n=n),fg=_c("green")); self._rp()
        except Exception as ex: self._ds.config(text=str(ex),fg=_c("acc"))

    def _imp_enc(self):
        p=filedialog.askopenfilename(parent=self,filetypes=[("NullPass Encrypted","*.npx"),("All","*.*")])
        if not p: return
        dlg=_PwPr(self,"",T("imp_pw")); self.wait_window(dlg)
        if not dlg.result: return
        try: n=self._v.import_enc(p,dlg.result); self._ds.config(text=T("imported",n=n),fg=_c("green")); self._rp()
        except: self._ds.config(text="Wrong password or corrupt file",fg=_c("acc"))

    def _do_bk(self):
        try: dst=self._v.backup(); self._bk_lbl.config(text=T("bk_saved",name=dst.name),fg=_c("green"))
        except Exception as ex: self._bk_lbl.config(text=str(ex),fg=_c("acc"))

    def _open_folder(self):
        d=str(_data())
        if IS_WIN: os.startfile(d)
        elif IS_MAC: subprocess.Popen(["open",d])
        else: subprocess.Popen(["xdg-open",d])

    def _rp(self):
        if hasattr(self._p,"_build_cats"): self._p._build_cats(); self._p._refresh()

    def _center(self, p):
        w,h=500,880
        x=p.winfo_rootx()+(p.winfo_width()-w)//2
        y=p.winfo_rooty()+(p.winfo_height()-h)//2
        self.geometry(f"{w}x{h}+{max(0,x)}+{max(0,y)}")


class GenPanel(tk.Frame):
    def __init__(self, p):
        super().__init__(p, bg=_c("bg2"), width=310); self.pack_propagate(False)
        self._last=""; self._hist=[]; self._build(); self._gen()

    def _build(self):
        hdr=tk.Frame(self, bg=_c("bg2"), padx=14, pady=11); hdr.pack(fill="x")
        tk.Label(hdr, text=T("generator"), bg=_c("bg2"), fg=_c("fg"),
                 font=F(11,b=True)).pack(side="left")
        cl=tk.Label(hdr, text="✕", bg=_c("bg2"), fg=_c("fg3"),
                    font=F(11), cursor="hand2"); cl.pack(side="right")
        cl.bind("<Button-1>", lambda ev: self.destroy())
        cl.bind("<Enter>", lambda ev: cl.config(fg=_c("acc")))
        cl.bind("<Leave>", lambda ev: cl.config(fg=_c("fg3")))
        _div(self)

        body=tk.Frame(self, bg=_c("bg2"), padx=14, pady=12)
        body.pack(fill="both", expand=True)

        mf=tk.Frame(body, bg=_c("bg3"),
                    highlightthickness=1, highlightbackground=_c("line2"))
        mf.pack(fill="x",pady=(0,10))
        self._mode=tk.StringVar(value="random")
        for val,lbl2 in [("random",T("generate")),("phrase",T("passphrase")),
                          ("pin","PIN"),("memorable",T("memorable"))]:
            tk.Radiobutton(mf, text=lbl2, variable=self._mode, value=val,
                           command=self._on_mode,
                           bg=_c("bg3"), fg=_c("fg3"), selectcolor=_c("bg5"),
                           activebackground=_c("bg3"), activeforeground=_c("fg"),
                           indicatoron=False, relief="flat", font=F(8),
                           padx=6, pady=7, cursor="hand2").pack(
                               side="left",expand=True,fill="x")

        of=tk.Frame(body, bg=_c("card"),
                    highlightthickness=1, highlightbackground=_c("line2"))
        of.pack(fill="x",pady=(0,6))
        self._ov=tk.StringVar(value="")
        self._ol=tk.Label(of, textvariable=self._ov, bg=_c("card"), fg=_c("fg"),
                          font=F(12,m=True), padx=14, pady=14,
                          wraplength=270, justify="center", cursor="hand2")
        self._ol.pack(fill="x")
        self._ol.bind("<Button-1>", lambda ev: self._copy())
        _tip(self._ol,"Click to copy")

        self._sb=_SBar(body, h=3); self._sb.pack(fill="x",pady=(0,2))
        self._sl=tk.Label(body, text="", bg=_c("bg2"), fg=_c("fg3"),
                          font=F(7), anchor="w"); self._sl.pack(fill="x")
        tk.Frame(body, bg=_c("bg2"), height=8).pack()

        self._len_frame=tk.Frame(body, bg=_c("bg2")); self._len_frame.pack(fill="x",pady=(0,2))
        lr=tk.Frame(self._len_frame, bg=_c("bg2")); lr.pack(fill="x")
        tk.Label(lr, text=T("length"), bg=_c("bg2"), fg=_c("fg2"), font=F(9)).pack(side="left")
        self._ll=tk.Label(lr, text="20", bg=_c("bg2"), fg=_c("acc"),
                          font=F(9,b=True), width=4); self._ll.pack(side="right")
        self._lv=tk.IntVar(value=20)
        tk.Scale(self._len_frame, from_=4, to=80, orient="horizontal", variable=self._lv,
                 bg=_c("bg2"), fg=_c("fg2"), troughcolor=_c("bg3"),
                 activebackground=_c("acc"), highlightthickness=0, bd=0,
                 showvalue=False, command=self._on_len).pack(fill="x",pady=(0,6))

        self._pin_frame=tk.Frame(body, bg=_c("bg2"))
        tk.Label(self._pin_frame, text=T("pin_length")+":",
                 bg=_c("bg2"), fg=_c("fg3"), font=F(8)).pack(side="left")
        self._pin_v=tk.IntVar(value=6)
        tk.Spinbox(self._pin_frame, from_=4, to=12, textvariable=self._pin_v,
                   width=4, bg=_c("inp"), fg=_c("fg"),
                   buttonbackground=_c("btn"), relief="flat",
                   font=F(10), command=self._gen).pack(side="left",padx=(8,0),ipady=3)

        self._vars={}
        cf=tk.Frame(body, bg=_c("bg2")); cf.pack(fill="x",pady=(0,3))
        for i,(k,lb2,d) in enumerate([("up",T("uppercase"),True),
                                       ("lo",T("lowercase"),True),
                                       ("dg",T("digits"),True),
                                       ("sy",T("symbols"),True)]):
            v=tk.BooleanVar(value=d); self._vars[k]=v
            tk.Checkbutton(cf, text=lb2, variable=v, command=self._gen,
                           bg=_c("bg2"), fg=_c("fg2"), selectcolor=_c("bg5"),
                           activebackground=_c("bg2"), font=F(8),
                           pady=2).grid(row=i//2,column=i%2,sticky="w",padx=2)

        of2=tk.Frame(body, bg=_c("bg2")); of2.pack(fill="x",pady=(0,8))
        self._ambi=tk.BooleanVar(value=False); self._exsym=tk.BooleanVar(value=False)
        for txt2,var2 in [(T("no_ambiguous"),self._ambi),(T("extra_syms"),self._exsym)]:
            tk.Checkbutton(of2, text=txt2, variable=var2, command=self._gen,
                           bg=_c("bg2"), fg=_c("fg3"), selectcolor=_c("bg5"),
                           activebackground=_c("bg2"), font=F(8),
                           pady=1).pack(anchor="w",padx=2)

        _div(body, py=6)
        hr=tk.Frame(body, bg=_c("bg2")); hr.pack(fill="x",pady=(4,2))
        tk.Label(hr, text=T("recent"), bg=_c("bg2"), fg=_c("fg3"),
                 font=F(8), anchor="w").pack(side="left")
        clr=tk.Label(hr, text=T("clear"), bg=_c("bg2"), fg=_c("fg3"),
                     font=F(8), cursor="hand2"); clr.pack(side="right")
        clr.bind("<Button-1>", lambda ev: self._clr_hist())
        clr.bind("<Enter>", lambda ev: clr.config(fg=_c("acc")))
        clr.bind("<Leave>", lambda ev: clr.config(fg=_c("fg3")))
        self._hf=tk.Frame(body, bg=_c("bg2")); self._hf.pack(fill="x")

        _div(self)
        foot=tk.Frame(self, bg=_c("bg2"), padx=12, pady=9); foot.pack(fill="x")
        _Btn(foot, T("regen"), self._gen, py=7).pack(side="left")
        _ABt(foot, T("copy"), self._copy, py=7).pack(side="right")
        self.bind("<space>", lambda ev: self._gen())

    def _on_mode(self, *a):
        m=self._mode.get()
        if m=="pin":
            self._len_frame.pack_forget()
            self._pin_frame.pack(fill="x",pady=(0,8))
        else:
            self._pin_frame.pack_forget()
            self._len_frame.pack(fill="x",pady=(0,2))
        self._gen()

    def _on_len(self, v): self._ll.config(text=v); self._gen()

    def _gen(self, *a):
        m=self._mode.get()
        if m=="phrase": pw=mkphrase(max(3,self._lv.get()//5))
        elif m=="pin":
            ln=self._pin_v.get()
            pw="".join(secrets.choice(string.digits) for _ in range(ln))
        elif m=="memorable":
            pw=mkphrase(max(2,self._lv.get()//8),sep="",cap=True,num=True)
        else:
            kw={k:v.get() for k,v in self._vars.items()}
            kw["noamb"]=self._ambi.get(); kw["xsym"]=self._exsym.get()
            pw=mkpw(self._lv.get(),**kw)
        self._last=pw; self._ov.set(pw)
        self.after(50, lambda: self._sb.refresh(pw))
        sc,lb,col=pw_str(pw); bits=entropy(pw)
        self._sl.config(
            text=f"{lb}  ·  {bits} {T('bits')}  ·  {T('crack_time')}: {crack(bits)}",
            fg=col)
        self._add_hist(pw)

    def _add_hist(self, pw):
        self._hist.insert(0,pw); self._hist=self._hist[:6]
        for w in self._hf.winfo_children(): w.destroy()
        for p in self._hist:
            r=tk.Frame(self._hf, bg=_c("bg2")); r.pack(fill="x",pady=1)
            sc2,_,col2=pw_str(p)
            tk.Label(r, text="●", bg=_c("bg2"), fg=col2,
                     font=F(6)).pack(side="left",padx=(0,3))
            tk.Label(r, text=p, bg=_c("bg2"), fg=_c("fg3"),
                     font=F(8,m=True), anchor="w").pack(side="left",fill="x",expand=True)
            cv2=tk.Label(r, text=T("copy"), bg=_c("bg2"), fg=_c("fg3"),
                         font=F(7), cursor="hand2"); cv2.pack(side="right")
            cv2.bind("<Button-1>", lambda ev,pw=p: self._copy_str(pw))
            cv2.bind("<Enter>", lambda ev,w=cv2: w.config(fg=_c("acc")))
            cv2.bind("<Leave>", lambda ev,w=cv2: w.config(fg=_c("fg3")))

    def _clr_hist(self):
        self._hist=[]
        for w in self._hf.winfo_children(): w.destroy()

    def _copy(self): self._copy_str(self._last)

    def _copy_str(self, pw):
        try:
            self.winfo_toplevel().clipboard_clear()
            self.winfo_toplevel().clipboard_append(pw)
        except: pass
        old=self._ov.get(); self._ol.config(fg=_c("green"))
        self._ov.set(f"✓  {T('copied')}")
        self.after(1400, lambda: (self._ov.set(old), self._ol.config(fg=_c("fg"))))


class NullPass(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NullPass"); self.configure(bg=_c("bg"))
        self.minsize(1020,600); self.geometry("1260x760")
        self._set_icon(); self.vault=Vault()
        self._cur=None; self._filt=[]; self._clip_tok=None; self._clip_lbl=None
        self._totp_tid=None; self._sel_ids=set()
        self._sort=tk.StringVar(value="Name"); self._gen_panel=None
        self._show_first(); self.after(10000,self._tick)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _set_icon(self):
        img=_icon(32)
        if img: self._icon=img; self.iconphoto(True,self._icon)

    def _on_close(self): self.vault.lock(); self.destroy()
    def _clear(self): [w.destroy() for w in self.winfo_children()]

    def _show_first(self):
        cfg=_lcfg()
        if "lang" not in cfg:
            self._clear()
            LangScreen(self, self._after_lang).pack(fill="both",expand=True)
        else: self._show_unlock()

    def _after_lang(self): self._clear(); self._show_unlock()

    def _show_unlock(self):
        self._clear()
        UnlockScreen(self, self.vault, self._show_main).pack(fill="both",expand=True)

    def _show_main(self): self._clear(); self._build()

    def _tick(self):
        if self.vault.idle(): self.vault.lock(); self._show_unlock()
        else: self.after(10000,self._tick)

    def _build(self):
        top=tk.Frame(self, bg=_c("bg2"), height=52)
        top.pack(fill="x"); top.pack_propagate(False)
        tk.Frame(self, bg=_c("acc"), height=1).pack(fill="x")

        lf=tk.Frame(top, bg=_c("bg2")); lf.pack(side="left",padx=(16,0))
        ico=_icon(26)
        if ico: il=tk.Label(lf,image=ico,bg=_c("bg2")); il.image=ico; il.pack(side="left")
        tk.Label(lf, text="NullPass", bg=_c("bg2"), fg=_c("fg"),
                 font=F(12,b=True)).pack(side="left",padx=(8,0))

        sf2=tk.Frame(top, bg=_c("bg2")); sf2.pack(side="left",padx=14,fill="x",expand=True,pady=10)
        self._se=_Ent(sf2, ph=T("search")+"   Ctrl+F")
        self._se.pack(fill="x",ipady=7)
        self._se.bind("<KeyRelease>", self._on_search)
        self._se.bind("<Escape>", lambda ev: self._clear_search())

        bf=tk.Frame(top, bg=_c("bg2")); bf.pack(side="right",padx=12)
        for lbl2,cmd,tt in [(T("new"),     self._add,          "Ctrl+N"),
                             (T("generator"),self._toggle_gen,  "Ctrl+G"),
                             (T("audit"),   self._open_audit,   ""),
                             (T("trash"),   self._open_trash,   ""),
                             (T("settings"),self._open_settings,""),
                             (T("lock"),    self._lock,         "Ctrl+L")]:
            b=tk.Label(bf, text=lbl2, bg=_c("bg2"), fg=_c("fg3"),
                       font=F(9), padx=10, pady=18, cursor="hand2")
            b.pack(side="left")
            b.bind("<Enter>", lambda ev,w=b: w.config(fg=_c("fg"),bg=_c("bg3")))
            b.bind("<Leave>", lambda ev,w=b: w.config(fg=_c("fg3"),bg=_c("bg2")))
            b.bind("<Button-1>", lambda ev,c=cmd: c())
            if tt: _tip(b,tt)

        body=tk.Frame(self, bg=_c("bg")); body.pack(fill="both",expand=True)

        sb=tk.Frame(body, bg=_c("bg2"), width=270)
        sb.pack(side="left",fill="y"); sb.pack_propagate(False)
        tk.Frame(body, bg=_c("line"), width=1).pack(side="left",fill="y")

        sbt=tk.Frame(sb, bg=_c("bg2"), padx=10, pady=10); sbt.pack(fill="x")

        self._tab=tk.StringVar(value="all"); self._tbtns={}
        tabf=tk.Frame(sbt, bg=_c("bg2")); tabf.pack(fill="x",pady=(0,6))
        for val,lbl2 in [("all",T("all")),("fav","★"),
                          ("pin",T("pinned")),("weak",T("weak")),("2fa","2FA")]:
            b=tk.Label(tabf, text=lbl2, bg=_c("bg2"), fg=_c("fg3"),
                       font=F(9), padx=7, pady=4, cursor="hand2")
            b.pack(side="left"); self._tbtns[val]=b
            b.bind("<Button-1>", lambda ev,v=val: self._set_tab(v))
        self._upd_tabs()

        sf3=tk.Frame(sbt, bg=_c("bg2")); sf3.pack(fill="x",pady=(4,0))
        tk.Label(sf3, text=T("sort_by")+":", bg=_c("bg2"), fg=_c("fg3"),
                 font=F(8)).pack(side="left")
        sm=tk.OptionMenu(sf3, self._sort, *SORTS, command=lambda v: self._refresh())
        sm.config(bg=_c("btn"), fg=_c("fg2"), activebackground=_c("btn_h"),
                  activeforeground=_c("fg"), relief="flat", font=F(8),
                  highlightthickness=0, bd=0, padx=6, pady=3)
        sm["menu"].config(bg=_c("btn"), fg=_c("fg2"),
                          activebackground=_c("sel"), activeforeground=_c("sel_fg"),
                          relief="flat")
        sm.pack(side="left",padx=(4,0))

        tk.Frame(sbt, bg=_c("line"), height=1).pack(fill="x",pady=(6,0))
        self._cnt=tk.Label(sbt, text="", bg=_c("bg2"), fg=_c("fg3"),
                           font=F(8), anchor="w"); self._cnt.pack(fill="x",pady=(5,0))

        self._catvar=tk.StringVar(value="")
        self._catf=tk.Frame(sb, bg=_c("bg2")); self._catf.pack(fill="x",padx=10,pady=(2,4))
        self._build_cats()

        self._lb=tk.Listbox(sb, bg=_c("bg2"), fg=_c("fg2"),
                            selectbackground=_c("sel"), selectforeground=_c("sel_fg"),
                            activestyle="none", relief="flat", bd=0, font=F(10),
                            highlightthickness=0, selectborderwidth=0,
                            selectmode=tk.EXTENDED)
        self._lb.pack(fill="both",expand=True)
        self._lb.bind("<<ListboxSelect>>", self._on_sel)
        self._lb.bind("<Double-Button-1>", lambda ev: self._edit())
        self._lb.bind("<Delete>", lambda ev: self._del_sel())
        self._lb.bind("<MouseWheel>",
                      lambda ev: self._lb.yview_scroll(int(-1*(ev.delta/120)),"units"))
        self._lb.bind("<Button-4>", lambda ev: self._lb.yview_scroll(-1,"units"))
        self._lb.bind("<Button-5>", lambda ev: self._lb.yview_scroll(1,"units"))
        self._lb.bind("<Button-3>", self._ctx)

        tk.Frame(sb, bg=_c("line"), height=1).pack(fill="x")
        self._bulk_f=tk.Frame(sb, bg=_c("bg2"), padx=10, pady=6); self._bulk_f.pack(fill="x")
        self._bulk_lbl=tk.Label(self._bulk_f, text="", bg=_c("bg2"), fg=_c("fg3"),
                                font=F(8), anchor="w"); self._bulk_lbl.pack(fill="x")
        self._bulk_acts=tk.Frame(self._bulk_f, bg=_c("bg2")); self._bulk_acts.pack(fill="x")
        self._sb_st=tk.Label(self._bulk_f, text="", bg=_c("bg2"), fg=_c("fg3"),
                             font=F(8), anchor="w"); self._sb_st.pack(fill="x")

        self._right=tk.Frame(body, bg=_c("bg")); self._right.pack(fill="both",expand=True)
        self._detail_f=tk.Frame(self._right, bg=_c("bg"))
        self._detail_f.pack(side="left",fill="both",expand=True)

        self._bind_keys(); self._refresh(); self._empty_detail()

    def _bind_keys(self):
        self.bind("<Control-n>", lambda ev: self._add())
        self.bind("<Control-f>", lambda ev: (self._se.focus_set(),
                                              self._se.select_range(0,tk.END)))
        self.bind("<Control-g>", lambda ev: self._toggle_gen())
        self.bind("<Control-l>", lambda ev: self._lock())
        self.bind("<Control-d>", lambda ev: self._dup_sel())
        self.bind("<Control-e>", lambda ev: self._edit())

    def _clear_search(self):
        self._se.delete(0,tk.END); self._se._dp(); self._on_search()

    def _toggle_gen(self):
        if self._gen_panel and self._gen_panel.winfo_exists():
            for w in self._right.winfo_children():
                if isinstance(w,tk.Frame) and w.cget("width")==1: w.destroy()
            self._gen_panel.destroy(); self._gen_panel=None
        else:
            tk.Frame(self._right, bg=_c("line"), width=1).pack(side="right",fill="y")
            self._gen_panel=GenPanel(self._right)
            self._gen_panel.pack(side="right",fill="y")

    def _set_tab(self, v): self._tab.set(v); self._upd_tabs(); self._on_search()

    def _upd_tabs(self):
        act=self._tab.get()
        for v,b in self._tbtns.items():
            b.config(fg=_c("acc") if v==act else _c("fg3"),
                     font=F(9,b=(v==act)))

    def _build_cats(self):
        for w in self._catf.winfo_children(): w.destroy()
        cats=[""]+self.vault.get_cats()
        if len(cats)<=2: return
        om=tk.OptionMenu(self._catf, self._catvar, *cats,
                         command=lambda v: self._on_search())
        om.config(bg=_c("btn"), fg=_c("fg2"), activebackground=_c("btn_h"),
                  activeforeground=_c("fg"), relief="flat", font=F(9),
                  highlightthickness=0, bd=0)
        om["menu"].config(bg=_c("btn"), fg=_c("fg2"),
                          activebackground=_c("sel"), activeforeground=_c("sel_fg"),
                          relief="flat")
        om.pack(fill="x")

    def _filtered(self):
        q=self._se.val().strip(); res=self.vault.search(q)
        t=self._tab.get()
        if t=="fav":  res=[e for e in res if e.get("favorite")]
        if t=="pin":  res=[e for e in res if e.get("pinned")]
        if t=="weak": res=[e for e in res if pw_str(e.get("password",""))[0]<50]
        if t=="2fa":  res=[e for e in res if e.get("totp","").strip()]
        cat=self._catvar.get()
        if cat: res=[e for e in res if e.get("category","")==cat]
        return self.vault.sort(res, self._sort.get())

    def _refresh(self, keep=False):
        self._filt=self._filtered(); self._lb.delete(0,tk.END)
        for e in self._filt:
            pin ="· " if e.get("pinned")   else "  "
            star="★ " if e.get("favorite") else "  "
            tf  ="⊕" if e.get("totp","").strip() else " "
            self._lb.insert(tk.END, f"  {pin}{star}{e['title']}  {tf}")
            sc,_,col=pw_str(e.get("password",""))
            try:
                if sc<50 and e.get("password"): self._lb.itemconfig(tk.END, fg=_c("acc"))
                elif e.get("favorite"):         self._lb.itemconfig(tk.END, fg=_c("amber"))
            except: pass
        total=len(self.vault.entries); shown=len(self._filt)
        self._cnt.config(text=f"{shown} / {total}" if shown!=total else str(total))
        if keep and self._cur:
            for i,e in enumerate(self._filt):
                if e["id"]==self._cur:
                    self._lb.selection_set(i); self._lb.see(i); break

    def _on_search(self, *a): self.vault.touch(); self._refresh()

    def _on_sel(self, ev=None):
        sel=self._lb.curselection()
        if not sel: return
        self._sel_ids={self._filt[i]["id"] for i in sel if i<len(self._filt)}
        if len(sel)==1:
            e=self._filt[sel[0]]; self._cur=e["id"]
            self.vault.touch_entry(e["id"]); self._detail(e); self.vault.touch()
            self._bulk_lbl.config(text=""); self._upd_bulk(False)
        else:
            self._cur=None
            self._empty_detail(msg=f"{len(sel)} {T('selected')}")
            self._bulk_lbl.config(text=f"{len(sel)} {T('selected')}")
            self._upd_bulk(True)

    def _upd_bulk(self, show):
        for w in self._bulk_acts.winfo_children(): w.destroy()
        if not show: return
        _ABt(self._bulk_acts, T("delete"), self._bulk_delete,
             py=4, danger=True, sm=True).pack(side="left",pady=(4,0))
        ov=tk.StringVar(value="Move…")
        om=tk.OptionMenu(self._bulk_acts, ov, "Move…", *CATS,
                         command=lambda cat: self._bulk_move(cat))
        om.config(bg=_c("btn"), fg=_c("fg3"), activebackground=_c("btn_h"),
                  activeforeground=_c("fg"), relief="flat", font=F(8),
                  highlightthickness=0, bd=0)
        om["menu"].config(bg=_c("btn"), fg=_c("fg2"),
                          activebackground=_c("sel"), activeforeground=_c("sel_fg"),
                          relief="flat")
        om.pack(side="left",padx=(4,0),pady=(4,0))

    def _bulk_delete(self):
        if not messagebox.askyesno("",f"Move {len(self._sel_ids)} entries to Trash?",parent=self): return
        for eid in list(self._sel_ids): self.vault.delete(eid)
        self._cur=None; self._sel_ids=set()
        self._build_cats(); self._refresh(); self._empty_detail()
        self._bulk_lbl.config(text=""); self._upd_bulk(False)

    def _bulk_move(self, cat):
        if cat=="Move…": return
        self.vault.move_cat(self._sel_ids, cat); self._build_cats(); self._refresh(True)

    def _del_sel(self):
        sel=self._lb.curselection()
        if not sel: return
        if len(sel)==1: self._delete(self._filt[sel[0]]["id"])
        else: self._bulk_delete()

    def _dup_sel(self):
        if not self._cur: return
        e=self.vault.duplicate(self._cur)
        if e:
            self._cur=e["id"]; self._build_cats(); self._refresh(); self._detail(e)
            self._sb_st.config(text=T("dup_ok",t=e["title"]))
            self.after(3000, lambda: self._sb_st.config(text=""))

    def _ctx(self, ev):
        idx=self._lb.nearest(ev.y); sel=self._lb.curselection()
        if idx not in sel:
            self._lb.selection_clear(0,tk.END); self._lb.selection_set(idx); self._on_sel()
        if not self._cur: return
        entry=next((e for e in self.vault.entries if e["id"]==self._cur), None)
        m=tk.Menu(self, tearoff=0, bg=_c("bg3"), fg=_c("fg2"),
                  activebackground=_c("sel"), activeforeground=_c("sel_fg"),
                  relief="flat", bd=1)
        m.add_command(label=f"{T('edit')}  Ctrl+E",     command=self._edit)
        m.add_command(label=f"{T('duplicate')}  Ctrl+D",command=self._dup_sel)
        m.add_separator()
        if entry:
            m.add_command(
                label=("★ "+T("favorites")) if not entry.get("favorite") else "Remove ★",
                command=self._tog_fav)
            m.add_command(
                label="Pin" if not entry.get("pinned") else "Unpin",
                command=self._tog_pin)
        m.add_separator()
        m.add_command(label=T("delete"), command=lambda: self._delete(self._cur))
        try: m.tk_popup(ev.x_root,ev.y_root)
        finally: m.grab_release()

    def _tog_fav(self):
        if not self._cur: return
        self.vault.toggle_fav(self._cur)
        ne=next((e for e in self.vault.entries if e["id"]==self._cur), None)
        if ne: self._refresh(True); self._detail(ne)

    def _tog_pin(self):
        if not self._cur: return
        self.vault.toggle_pin(self._cur)
        ne=next((e for e in self.vault.entries if e["id"]==self._cur), None)
        if ne: self._refresh(True); self._detail(ne)

    def _empty_detail(self, msg=None):
        for w in self._detail_f.winfo_children(): w.destroy()
        c=tk.Frame(self._detail_f, bg=_c("bg")); c.place(relx=0.5,rely=0.44,anchor="center")
        if msg:
            tk.Label(c, text=msg, bg=_c("bg"), fg=_c("fg2"), font=F(15)).pack(pady=(0,6))
            tk.Label(c, text="Shift+click  ·  multi-select",
                     bg=_c("bg"), fg=_c("fg3"), font=F(9)).pack()
        else:
            ico=_icon(48)
            if ico: il=tk.Label(c,image=ico,bg=_c("bg")); il.image=ico; il.pack()
            tk.Label(c, text="NullPass", bg=_c("bg"), fg=_c("fg"),
                     font=F(16,b=True)).pack(pady=(12,2))
            tk.Label(c, text=T("no_entries") if not self.vault.entries else "Select an entry",
                     bg=_c("bg"), fg=_c("fg3"), font=F(10)).pack()
            if not self.vault.entries:
                tk.Label(c, text=T("add_first"), bg=_c("bg"), fg=_c("fg3"),
                         font=F(9)).pack(pady=(4,0))
            kf=tk.Frame(c, bg=_c("bg")); kf.pack(pady=(16,0))
            for key,lbl2 in [("Ctrl+N",T("new")),("Ctrl+F",T("search")),
                              ("Ctrl+G",T("generator")),("Ctrl+L",T("lock"))]:
                kb=tk.Frame(kf, bg=_c("bg4"), padx=7, pady=4,
                            highlightthickness=1, highlightbackground=_c("line2"))
                kb.pack(side="left",padx=3)
                tk.Label(kb, text=key, bg=_c("bg4"), fg=_c("acc"),
                         font=F(8,b=True)).pack(side="left")
                tk.Label(kb, text=f"  {lbl2}", bg=_c("bg4"), fg=_c("fg3"),
                         font=F(8)).pack(side="left")
        if self.vault.entries and not msg:
            st=self.vault.stats(); stf=tk.Frame(c, bg=_c("bg")); stf.pack(pady=(20,0))
            for lbl2,val,col in [("total",st["total"],_c("fg")),
                                   ("★",st["fav"],_c("amber")),
                                   (T("weak"),st["weak"],_c("acc") if st["weak"] else _c("fg3")),
                                   ("2FA",st["with_2fa"],_c("green") if st["with_2fa"] else _c("fg3"))]:
                sf4=tk.Frame(stf, bg=_c("card"), padx=15, pady=12,
                             highlightthickness=1, highlightbackground=_c("line"))
                sf4.pack(side="left",padx=4)
                tk.Label(sf4, text=str(val), bg=_c("card"), fg=col,
                         font=F(16,b=True)).pack()
                tk.Label(sf4, text=lbl2, bg=_c("card"), fg=_c("fg3"),
                         font=F(8)).pack()

    def _detail(self, entry):
        self._cancel_totp()
        for w in self._detail_f.winfo_children(): w.destroy()
        self.vault.touch(); self._clip_lbl=None

        hdr=tk.Frame(self._detail_f, bg=_c("bg2"), padx=22, pady=14); hdr.pack(fill="x")
        lh=tk.Frame(hdr, bg=_c("bg2")); lh.pack(side="left",fill="x",expand=True)
        tk.Label(lh, text=entry["title"], bg=_c("bg2"), fg=_c("fg"),
                 font=F(17,b=True), anchor="w").pack(anchor="w")
        meta=tk.Frame(lh, bg=_c("bg2")); meta.pack(anchor="w",pady=(4,0))
        tk.Label(meta, text=entry.get("category","General"),
                 bg=_c("bg3"), fg=_c("fg3"), font=F(8), padx=7, pady=2).pack(side="left")
        url=entry.get("url","")
        if url.startswith("http"):
            tk.Label(meta, text=f"  {_dom(url)}", bg=_c("bg2"),
                     fg=_c("fg3"), font=F(8)).pack(side="left")
        uses=entry.get("use_count",0); last=entry.get("last_used")
        info=f"  ·  {uses} {T('uses')}"
        if last: info+=f"  ·  {T('last_used')}: {_fmt(last)}"
        tk.Label(meta, text=info, bg=_c("bg2"), fg=_c("fg3"), font=F(8)).pack(side="left")

        br=tk.Frame(hdr, bg=_c("bg2")); br.pack(side="right")
        fav_c=_c("amber") if entry.get("favorite") else _c("fg3")
        pin_c=_c("acc")   if entry.get("pinned")   else _c("fg3")
        for txt,col,tt,cmd in [("📌",pin_c,T("pinned"),self._tog_pin),
                                ("★",fav_c,T("favorites"),self._tog_fav)]:
            b=tk.Label(br, text=txt, bg=_c("bg2"), fg=col,
                       font=F(12), padx=6, pady=10, cursor="hand2")
            b.pack(side="left"); b.bind("<Button-1>",lambda ev,c=cmd: c()); _tip(b,tt)
        _Btn(br, T("edit"),      self._edit,                     py=7).pack(side="left",padx=(4,0))
        _Btn(br, T("duplicate"), self._dup_sel,                  py=7).pack(side="left",padx=(4,0))
        _ABt(br, T("delete"),    lambda: self._delete(entry["id"]),
             py=7, danger=True, sm=True).pack(side="left",padx=(4,0))
        _div(self._detail_f)

        sf5=_SF(self._detail_f, bg=_c("bg")); sf5.pack(fill="both",expand=True); b=sf5.inner
        self._clip_lbl=tk.Label(b, text="", bg=_c("bg"), fg=_c("green"),
                                font=F(9), anchor="w")
        self._clip_lbl.pack(fill="x",padx=22,pady=(10,0))

        clip_s=self.vault._clip_s

        def _copy(val, name):
            self.clipboard_clear(); self.clipboard_append(val); self.update()
            if self._clip_lbl:
                t=f"✓  {name}: {T('copied')}"
                if clip_s>0: t+=f"  ·  {T('clears_in')} {clip_s}s"
                self._clip_lbl.config(text=t, fg=_c("green"))
            if self._clip_tok: self.after_cancel(self._clip_tok)
            if clip_s>0: self._clip_tok=self.after(clip_s*1000, self._clr_clip)

        def field(lbl, val, secret=False, url_btn=False, mono=False):
            if not val: return
            row=tk.Frame(b, bg=_c("card"),
                         highlightthickness=1, highlightbackground=_c("line"))
            row.pack(fill="x",padx=22,pady=3)
            inn=tk.Frame(row, bg=_c("card"), padx=14, pady=10); inn.pack(fill="x")
            tk.Label(inn, text=lbl, bg=_c("card"), fg=_c("fg3"),
                     font=F(9), width=11, anchor="w").pack(side="left")
            disp="●"*min(len(val),28) if secret else val
            vis=[False]
            vl=tk.Label(inn, text=disp, bg=_c("card"), fg=_c("fg"),
                        font=F(11,m=(secret or mono)), anchor="w", wraplength=400)
            vl.pack(side="left",fill="x",expand=True)
            act=tk.Frame(inn, bg=_c("card")); act.pack(side="right")
            cb=tk.Label(act, text=T("copy"), bg=_c("card"), fg=_c("fg3"),
                        font=F(8), padx=6, cursor="hand2")
            cb.pack(side="right")
            cb.bind("<Button-1>", lambda ev,v=val,n=lbl: _copy(v,n))
            cb.bind("<Enter>", lambda ev: cb.config(fg=_c("acc")))
            cb.bind("<Leave>", lambda ev: cb.config(fg=_c("fg3")))
            if secret:
                def _tog(lb=vl,v=val,s=vis):
                    s[0]=not s[0]; lb.config(text=v if s[0] else "●"*min(len(v),28))
                eye=tk.Label(act, text=T("show"), bg=_c("card"), fg=_c("fg3"),
                             font=F(8), padx=6, cursor="hand2")
                eye.pack(side="right"); eye.bind("<Button-1>",lambda ev: _tog())
                eye.bind("<Enter>", lambda ev: eye.config(fg=_c("fg")))
                eye.bind("<Leave>", lambda ev: eye.config(fg=_c("fg3")))
            if url_btn and val.startswith("http"):
                gl=tk.Label(act, text=T("open"), bg=_c("card"), fg=_c("sky"),
                            font=F(8), padx=6, cursor="hand2")
                gl.pack(side="right"); gl.bind("<Button-1>",lambda ev,u=val: webbrowser.open(u))
                gl.bind("<Enter>", lambda ev: gl.config(fg=_c("fg")))
                gl.bind("<Leave>", lambda ev: gl.config(fg=_c("sky")))

        field(T("username"), entry.get("username",""))
        field(T("password"), entry.get("password",""), secret=True)
        field("URL",         entry.get("url",""),      url_btn=True)
        for cf in entry.get("custom_fields",[]):
            if cf.get("label") and cf.get("value"):
                field(cf["label"], cf["value"], secret=cf.get("secret",False), mono=True)

        tags=entry.get("tags",[])
        if tags:
            tr=tk.Frame(b, bg=_c("bg")); tr.pack(fill="x",padx=22,pady=3)
            tk.Label(tr, text=T("tags"), bg=_c("bg"), fg=_c("fg3"),
                     font=F(9), width=11, anchor="w").pack(side="left")
            for t in tags:
                tk.Label(tr, text=t, bg=_c("tag_bg"), fg=_c("tag_fg"),
                         font=F(9), padx=7, pady=2).pack(side="left",padx=(0,4))

        totp_s=entry.get("totp","").strip()
        if totp_s:
            tr2=tk.Frame(b, bg=_c("card"),
                         highlightthickness=1, highlightbackground=_c("line"))
            tr2.pack(fill="x",padx=22,pady=3)
            in2=tk.Frame(tr2, bg=_c("card"), padx=14, pady=10); in2.pack(fill="x")
            tk.Label(in2, text="2FA", bg=_c("card"), fg=_c("fg3"),
                     font=F(9), width=11, anchor="w").pack(side="left")
            self._totp_v=tk.StringVar(value="")
            self._totp_r=tk.StringVar(value="")
            clbl=tk.Label(in2, textvariable=self._totp_v, bg=_c("card"),
                          fg=_c("green"), font=F(20,b=True,m=True))
            clbl.pack(side="left",padx=(0,8))
            tk.Label(in2, textvariable=self._totp_r, bg=_c("card"),
                     fg=_c("fg3"), font=F(8)).pack(side="left")
            ctb=tk.Label(in2, text=T("copy"), bg=_c("card"), fg=_c("fg3"),
                         font=F(8), padx=6, cursor="hand2"); ctb.pack(side="right")
            ctb.bind("<Button-1>", lambda ev: _copy(self._totp_v.get(),"2FA"))
            ctb.bind("<Enter>", lambda ev: ctb.config(fg=_c("acc")))
            ctb.bind("<Leave>", lambda ev: ctb.config(fg=_c("fg3")))
            def _tick(s=totp_s, cl=clbl):
                try:
                    code,rem=do_totp(s); self._totp_v.set(code); self._totp_r.set(f"{rem}s")
                    cl.config(fg=_c("green") if rem>12 else _c("amber") if rem>6 else _c("acc"))
                except: pass
                self._totp_tid=self.after(1000,_tick)
            _tick()

        pw=entry.get("password","")
        if pw:
            sc,lb,col=pw_str(pw); bits=entropy(pw)
            _div(b, px=22, py=4)
            sr=tk.Frame(b, bg=_c("bg")); sr.pack(fill="x",padx=22,pady=(6,2))
            tk.Label(sr, text=f"{T('strength')}:", bg=_c("bg"), fg=_c("fg3"),
                     font=F(9)).pack(side="left")
            tk.Label(sr, text=lb, bg=_c("bg"), fg=col,
                     font=F(9,b=True)).pack(side="left",padx=(6,0))
            tk.Label(sr, text=f"  ·  {bits} {T('bits')}  ·  {T('crack_time')}: {crack(bits)}",
                     bg=_c("bg"), fg=_c("fg3"), font=F(8)).pack(side="left")
            bar=_SBar(b,h=3); bar.pack(fill="x",padx=22,pady=(0,8))
            self.after(60, lambda bar=bar,p=pw: bar.refresh(p))

        notes=entry.get("notes","").strip()
        if notes:
            _div(b, px=22, py=4)
            tk.Label(b, text=T("notes"), bg=_c("bg"), fg=_c("fg3"),
                     font=F(9), anchor="w").pack(anchor="w",padx=22,pady=(8,2))
            nb=tk.Text(b, bg=_c("card"), fg=_c("fg2"), relief="flat", font=F(10),
                       highlightthickness=1, highlightbackground=_c("line"),
                       height=min(8,notes.count("\n")+2), width=1)
            nb.pack(fill="x",padx=22,pady=(0,8))
            nb.insert("1.0",notes); nb.config(state="disabled")

        _div(b, px=22, py=4)
        cr=entry.get("created","")[:10]; mo=entry.get("modified","")[:10]
        pwc=entry.get("pw_changed","")[:10]
        info=f"{T('created')}: {cr}  ·  {T('modified')}: {mo}"
        if pwc and pwc!=mo: info+=f"  ·  {T('pw_changed')}: {pwc}"
        tk.Label(b, text=info, bg=_c("bg"), fg=_c("fg4"), font=F(8)).pack(
            anchor="w",padx=22,pady=(8,22))

    def _cancel_totp(self):
        if self._totp_tid:
            try: self.after_cancel(self._totp_tid)
            except: pass
            self._totp_tid=None

    def _clr_clip(self):
        try: self.clipboard_clear(); self.update()
        except: pass
        if self._clip_lbl: self._clip_lbl.config(text="")

    def _add(self):
        dlg=EntryDlg(self,self.vault); self.wait_window(dlg)
        if dlg.result:
            e=self.vault.add(**dlg.result); self._cur=e["id"]
            self._build_cats(); self._refresh(); self._detail(e)
            self._sb_st.config(text=f"+ {e['title']}")
            self.after(3000, lambda: self._sb_st.config(text=""))

    def _edit(self):
        if not self._cur: return
        entry=next((e for e in self.vault.entries if e["id"]==self._cur), None)
        if not entry: return
        dlg=EntryDlg(self,self.vault,entry); self.wait_window(dlg)
        if dlg.result:
            self.vault.update(self._cur,**dlg.result)
            upd=next(e for e in self.vault.entries if e["id"]==self._cur)
            self._build_cats(); self._refresh(True); self._detail(upd)

    def _delete(self, eid):
        entry=next((e for e in self.vault.entries if e["id"]==eid), None)
        name=entry["title"] if entry else "?"
        if not messagebox.askyesno("",T("del_confirm",name=name),parent=self): return
        self._cancel_totp(); self.vault.delete(eid); self._cur=None
        self._build_cats(); self._refresh(); self._empty_detail()

    def _lock(self):
        self._cancel_totp(); self.vault.lock(); self._cur=None; self._show_unlock()

    def _open_audit(self):    AuditDlg(self,self.vault)
    def _open_trash(self):    TrashDlg(self,self.vault)
    def _open_settings(self): SettingsDlg(self,self.vault)


if __name__ == "__main__":
    cfg=_lcfg()
    _LANG=cfg.get("lang","en")
    _apply(cfg.get("theme","dark"))
    app=NullPass(); app.mainloop()
