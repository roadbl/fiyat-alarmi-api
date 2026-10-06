from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import threading
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, request
from flask_cors import CORS

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DB_PATH", str(BASE_DIR / "price_alarm.db")))

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "").strip()
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/")
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
CHECK_INTERVAL_MINUTES = max(5, int(os.getenv("CHECK_INTERVAL_MINUTES", "30")))
ALERT_MIN_CONFIDENCE = float(os.getenv("ALERT_MIN_CONFIDENCE", "0.65"))
FETCH_TOP_CANDIDATES = max(1, min(8, int(os.getenv("FETCH_TOP_CANDIDATES", "5"))))
ENABLE_SCHEDULER = os.getenv("ENABLE_SCHEDULER", "true").lower() in {"1", "true", "yes", "on"}

ALLOWED_ORIGINS = [
    x.strip()
    for x in os.getenv(
        "ALLOWED_ORIGINS",
        "https://roadbl.github.io,http://127.0.0.1:5500,http://localhost:5500"
    ).split(",")
    if x.strip()
]

TRUSTED_DOMAINS = [
    x.strip().lower()
    for x in os.getenv(
        "TRUSTED_DOMAINS",
        ",".join([
            "amazon.com.tr", "hepsiburada.com", "trendyol.com", "n11.com",
            "mediamarkt.com.tr", "teknosa.com", "vatanbilgisayar.com",
            "pazarama.com", "migros.com.tr", "carrefoursa.com",
            "apple.com", "samsung.com", "mi.com", "dyson.com.tr",
            "philips.com.tr", "bosch-home.com.tr", "arcelik.com.tr", "beko.com.tr"
        ])
    ).split(",")
    if x.strip()
]

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "")
SMTP_SECURITY = os.getenv("SMTP_SECURITY", "starttls").lower()

UA = (
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36"
)

app = Flask(__name__)
CORS(
    app,
    resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
    methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Manage-Token"],
)

_scheduler_started = False
_scheduler_lock = threading.Lock()
_stop_event = threading.Event()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS trackers (
            id TEXT PRIMARY KEY,
            manage_token_hash TEXT NOT NULL,
            query TEXT NOT NULL,
            product_name TEXT,
            source_url TEXT,
            target_price REAL NOT NULL,
            currency TEXT NOT NULL DEFAULT 'TRY',
            email TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_checked_at TEXT,
            last_price REAL,
            last_source TEXT,
            last_url TEXT,
            last_confidence REAL,
            last_error TEXT,
            last_notified_price REAL,
            notified_at TEXT
        );

        CREATE TABLE IF NOT EXISTS price_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracker_id TEXT NOT NULL,
            source TEXT NOT NULL,
            url TEXT NOT NULL,
            price REAL NOT NULL,
            currency TEXT NOT NULL,
            confidence REAL NOT NULL,
            checked_at TEXT NOT NULL
        );
        """)
        conn.commit()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def secure_compare(token: str, stored_hash: str) -> bool:
    return secrets.compare_digest(hash_token(token), stored_hash)


def host_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower().removeprefix("www.")


def domain_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def trust_score(url: str) -> float:
    host = host_from_url(url)
    return 0.96 if any(domain_matches(host, d) for d in TRUSTED_DOMAINS) else 0.50


def is_public_http_url(url: str) -> bool:
    try:
        p = urlparse(url)
        if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
            return False

        infos = socket.getaddrinfo(
            p.hostname,
            p.port or (443 if p.scheme == "https" else 80)
        )
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if (
                ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified
            ):
                return False
        return bool(infos)
    except Exception:
        return False


def parse_number(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return v if 0 < v <= 100_000_000 else None

    s = re.sub(r"[^\d,.\-]", "", str(value).strip())
    if not s:
        return None

    if "," in s and "." in s:
        if s.rfind(",") > s.rfind("."):
            s = s.replace(".", "").replace(",", ".")
        else:
            s = s.replace(",", "")
    elif "," in s:
        right = s.split(",")[-1]
        s = s.replace(".", "").replace(",", ".") if len(right) in {1, 2} else s.replace(",", "")
    elif s.count(".") > 1:
        parts = s.split(".")
        s = "".join(parts[:-1]) + ("." + parts[-1] if len(parts[-1]) in {1, 2} else parts[-1])
    elif "." in s:
        left, right = s.rsplit(".", 1)
        if len(right) == 3 and len(left.replace("-", "")) <= 3:
            s = left + right

    try:
        v = float(s)
        return v if 0 < v <= 100_000_000 else None
    except ValueError:
        return None


def nvidia_json(system: str, user: str, max_tokens=1000, temperature=0.1):
    if not NVIDIA_API_KEY:
        return None

    r = requests.post(
        NVIDIA_BASE_URL + "/chat/completions",
        headers={
            "Authorization": f"Bearer {NVIDIA_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": NVIDIA_MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        },
        timeout=45,
    )
    r.raise_for_status()

    content = r.json()["choices"][0]["message"]["content"].strip()
    content = re.sub(r"^```(?:json)?\s*", "", content, flags=re.I)
    content = re.sub(r"\s*```$", "", content)
    match = re.search(r"\{.*\}", content, re.S)
    return json.loads(match.group(0) if match else content)


def ddg_search(query: str, max_results=12):
    r = requests.get(
        "https://html.duckduckgo.com/html/",
        params={"q": f"{query} fiyat satın al Türkiye"},
        headers={"User-Agent": UA, "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.7"},
        timeout=20,
    )
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")
    results, seen = [], set()

    for block in soup.select(".result"):
        a = block.select_one(".result__a")
        snippet = block.select_one(".result__snippet")
        if not a:
            continue

        href = a.get("href", "")
        if "duckduckgo.com/l/" in href or href.startswith("//duckduckgo.com/l/"):
            full = href if href.startswith("http") else "https:" + href
            qs = parse_qs(urlparse(full).query)
            href = unquote((qs.get("uddg") or [""])[0])

        if not href or href in seen or not is_public_http_url(href):
            continue

        seen.add(href)
        results.append({
            "title": a.get_text(" ", strip=True)[:500],
            "url": href,
            "snippet": snippet.get_text(" ", strip=True)[:1200] if snippet else "",
            "domain": host_from_url(href),
            "trust": trust_score(href),
            "match_score": 0.5,
        })

        if len(results) >= max_results:
            break

    results.sort(key=lambda x: x["trust"], reverse=True)
    return results


def rank_candidates(query: str, candidates: list[dict]) -> list[dict]:
    if not candidates:
        return []

    if not NVIDIA_API_KEY:
        q_words = {w.lower() for w in re.findall(r"[\w-]+", query) if len(w) > 2}
        for c in candidates:
            t_words = {w.lower() for w in re.findall(r"[\w-]+", c["title"])}
            overlap = len(q_words & t_words) / max(1, len(q_words))
            c["match_score"] = min(0.9, 0.35 + overlap * 0.65)
        return sorted(candidates, key=lambda c: c["match_score"] * c["trust"], reverse=True)

    payload = [
        {
            "index": i,
            "title": c["title"],
            "domain": c["domain"],
            "snippet": c["snippet"][:700],
        }
        for i, c in enumerate(candidates)
    ]

    try:
        data = nvidia_json(
            "Sen e-ticaret ürün eşleştirme uzmanısın. Yalnızca geçerli JSON döndür.",
            f"""Kullanıcı şu ürünü arıyor:
{query}

Aşağıdaki sonuçların gerçekten aynı ürünü/doğru varyantı satma olasılığını 0-1 puanla.
Aksesuar, yedek parça, farklı model/kapasite/beden, ikinci el ilan veya haber ise düşük puan ver.
Fiyat uydurma.

SADECE JSON:
{{"matches":[{{"index":0,"score":0.0,"reason":"kısa neden"}}]}}

Sonuçlar:
{json.dumps(payload, ensure_ascii=False)}""",
        )
        scores = {
            int(x["index"]): max(0, min(1, float(x["score"])))
            for x in data.get("matches", [])
        }
        for i, c in enumerate(candidates):
            c["match_score"] = scores.get(i, 0.25)
    except Exception:
        for c in candidates:
            c["match_score"] = 0.55

    return sorted(candidates, key=lambda c: c["match_score"] * c["trust"], reverse=True)


def safe_get(url: str):
    current = url
    for _ in range(4):
        if not is_public_http_url(current):
            raise ValueError("Güvenli olmayan URL")

        r = requests.get(
            current,
            headers={"User-Agent": UA, "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.7"},
            timeout=18,
            allow_redirects=False,
            stream=True,
        )

        if r.status_code in {301, 302, 303, 307, 308}:
            loc = r.headers.get("Location")
            if not loc:
                raise ValueError("Geçersiz yönlendirme")
            current = urljoin(current, loc)
            continue

        r.raise_for_status()

        ctype = (r.headers.get("Content-Type") or "").lower()
        if "html" not in ctype:
            raise ValueError("HTML içerik değil")

        data = bytearray()
        for chunk in r.iter_content(64 * 1024):
            data.extend(chunk)
            if len(data) > 2_000_000:
                break

        r._content = bytes(data)
        return r

    raise ValueError("Çok fazla yönlendirme")


def jsonld_objects(soup):
    for script in soup.find_all("script", attrs={"type": re.compile(r"application/ld\+json", re.I)}):
        raw = script.string or script.get_text(" ", strip=True)
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue

        stack = data if isinstance(data, list) else [data]
        while stack:
            obj = stack.pop()
            if isinstance(obj, dict):
                yield obj
                graph = obj.get("@graph")
                if isinstance(graph, list):
                    stack.extend(graph)
            elif isinstance(obj, list):
                stack.extend(obj)


def page_excerpt(soup, limit=12000):
    clone = BeautifulSoup(str(soup), "html.parser")
    for tag in clone(["script", "style", "noscript", "svg"]):
        tag.decompose()

    text = re.sub(r"\s+", " ", " ".join(clone.stripped_strings))
    windows = []

    for m in re.finditer(r"(?:₺|\bTL\b|\bTRY\b)", text, re.I):
        windows.append(text[max(0, m.start() - 350): min(len(text), m.end() + 350)])
        if sum(len(x) for x in windows) >= limit:
            break

    return (" ... ".join(windows) if windows else text)[:limit]


def extract_page(url: str):
    r = safe_get(url)
    soup = BeautifulSoup(r.text, "html.parser")

    og_title = soup.find("meta", property="og:title")
    title = (
        og_title.get("content") if og_title else None
    ) or (
        soup.title.get_text(" ", strip=True) if soup.title else host_from_url(r.url)
    )

    for obj in jsonld_objects(soup):
        types = obj.get("@type")
        types = types if isinstance(types, list) else [types]
        if not any(str(x).lower() == "product" for x in types if x):
            continue

        offers = obj.get("offers")
        offers = offers if isinstance(offers, list) else [offers] if isinstance(offers, dict) else []

        for offer in offers:
            ps = offer.get("priceSpecification") if isinstance(offer.get("priceSpecification"), dict) else {}
            price = parse_number(
                offer.get("price")
                or offer.get("lowPrice")
                or ps.get("price")
            )
            if price:
                return {
                    "url": r.url,
                    "title": obj.get("name") or title,
                    "source": host_from_url(r.url),
                    "price": price,
                    "currency": str(
                        offer.get("priceCurrency")
                        or ps.get("priceCurrency")
                        or "TRY"
                    ).upper(),
                    "extract_confidence": 0.98,
                    "excerpt": page_excerpt(soup),
                }

    meta_pairs = [
        ("property", "product:price:amount"),
        ("property", "og:price:amount"),
        ("name", "product:price:amount"),
        ("itemprop", "price"),
    ]

    amount = None
    for attr, key in meta_pairs:
        tag = soup.find("meta", attrs={attr: key})
        if tag and tag.get("content"):
            amount = tag["content"]
            break

    price = parse_number(amount)
    if price:
        return {
            "url": r.url,
            "title": title,
            "source": host_from_url(r.url),
            "price": price,
            "currency": "TRY",
            "extract_confidence": 0.92,
            "excerpt": page_excerpt(soup),
        }

    return {
        "url": r.url,
        "title": title,
        "source": host_from_url(r.url),
        "price": None,
        "currency": None,
        "extract_confidence": 0.0,
        "excerpt": page_excerpt(soup),
    }


def ai_price_fallback(query: str, page: dict):
    if not NVIDIA_API_KEY or not page["excerpt"]:
        return None

    try:
        data = nvidia_json(
            "Yalnızca verilen sayfa metninden kanıtlı fiyat çıkar. JSON dışında yazma.",
            f"""Aranan ürün: {query}
Sayfa başlığı: {page['title']}

Aşağıdaki metinden SADECE aranan ürünün güncel satış fiyatını çıkar.
Kupon, taksit, kargo, eski fiyat veya aksesuar fiyatını alma.
Emin değilsen found=false de. Asla uydurma.

SADECE JSON:
{{"found":true,"price":1234.56,"currency":"TRY","evidence":"sayfadan kısa birebir kanıt","confidence":0.0}}

Metin:
{page['excerpt']}""",
            max_tokens=700,
            temperature=0.0,
        )

        if not data or not data.get("found"):
            return None

        price = float(data["price"])
        conf = float(data.get("confidence", 0))
        evidence = re.sub(r"\s+", " ", str(data.get("evidence", "")).strip()).lower()
        page_text = re.sub(r"\s+", " ", page["excerpt"]).lower()

        if (
            not evidence
            or evidence not in page_text
            or conf < 0.70
            or not (0 < price <= 100_000_000)
        ):
            return None

        return {
            "price": price,
            "currency": str(data.get("currency") or "TRY").upper(),
            "confidence": min(conf, 0.85),
        }
    except Exception:
        return None


def send_email(to_email, product_name, target, price, currency, source, url, confidence):
    if not SMTP_HOST or not SMTP_FROM_EMAIL:
        return False, "SMTP ayarlı değil."

    msg = EmailMessage()
    msg["Subject"] = f"Fiyat alarmı: {product_name} {price:.2f} {currency}"
    msg["From"] = SMTP_FROM_EMAIL
    msg["To"] = to_email
    msg.set_content(
        f"""Hedef fiyat yakalandı.

Ürün: {product_name}
Hedef: {target:.2f} {currency}
Yeni fiyat: {price:.2f} {currency}
Kaynak: {source}
Güven: %{confidence * 100:.0f}

{url}

Satın almadan önce fiyatı ve ürün varyantını mağazada tekrar kontrol et.
"""
    )

    try:
        if SMTP_SECURITY == "ssl":
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)

        with server:
            server.ehlo()
            if SMTP_SECURITY == "starttls":
                server.starttls()
                server.ehlo()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        return True, "E-posta gönderildi."
    except Exception as e:
        return False, f"E-posta gönderilemedi: {e}"


def public_tracker(t):
    return {
        "id": t["id"],
        "query": t["query"],
        "product_name": t["product_name"],
        "source_url": t["source_url"],
        "target_price": t["target_price"],
        "currency": t["currency"],
        "email": t["email"],
        "active": bool(t["active"]),
        "created_at": t["created_at"],
        "last_checked_at": t["last_checked_at"],
        "last_price": t["last_price"],
        "last_source": t["last_source"],
        "last_url": t["last_url"],
        "last_confidence": t["last_confidence"],
        "last_error": t["last_error"],
        "notified_at": t["notified_at"],
    }


def auth_tracker(tracker_id: str):
    token = request.headers.get("X-Manage-Token", "")
    with db() as conn:
        tracker = conn.execute(
            "SELECT * FROM trackers WHERE id=?",
            (tracker_id,)
        ).fetchone()

    if not tracker:
        return None, (jsonify({"error": "Alarm bulunamadı."}), 404)

    if not token or not secure_compare(token, tracker["manage_token_hash"]):
        return None, (jsonify({"error": "Geçersiz yönetim anahtarı."}), 403)

    return tracker, None


def check_tracker(tracker_id: str):
    with db() as conn:
        t = conn.execute(
            "SELECT * FROM trackers WHERE id=?",
            (tracker_id,)
        ).fetchone()

        if not t:
            return {"ok": False, "error": "Alarm bulunamadı."}
        if not t["active"]:
            return {"ok": False, "error": "Alarm pasif."}

        try:
            parsed_query = urlparse(t["query"])
            direct_url = t["source_url"] or (
                t["query"] if parsed_query.scheme in {"http", "https"} and parsed_query.hostname else None
            )

            if direct_url:
                candidates = [{
                    "title": t["product_name"] or t["query"],
                    "url": direct_url,
                    "snippet": "Doğrudan kullanıcı bağlantısı",
                    "domain": host_from_url(direct_url),
                    "trust": trust_score(direct_url),
                    "match_score": 1.0,
                }]
            else:
                candidates = rank_candidates(t["query"], ddg_search(t["query"]))

            if not candidates:
                raise RuntimeError("Uygun web sonucu bulunamadı.")

            observations = []
            best_title = None

            for c in candidates[:FETCH_TOP_CANDIDATES]:
                if c["match_score"] < 0.35 and c["trust"] < 0.9:
                    continue

                try:
                    page = extract_page(c["url"])
                    best_title = best_title or page["title"]

                    price = page["price"]
                    currency = (page["currency"] or t["currency"]).upper()
                    extract_conf = page["extract_confidence"]

                    if price is None:
                        ai = ai_price_fallback(t["query"], page)
                        if ai:
                            price = ai["price"]
                            currency = ai["currency"]
                            extract_conf = ai["confidence"]

                    if price is None or currency != t["currency"].upper():
                        continue

                    confidence = min(
                        1.0,
                        c["match_score"] * 0.35
                        + c["trust"] * 0.25
                        + extract_conf * 0.40
                    )

                    checked = utcnow_iso()
                    conn.execute(
                        """INSERT INTO price_observations
                           (tracker_id, source, url, price, currency, confidence, checked_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            t["id"], page["source"], page["url"],
                            price, currency, confidence, checked
                        ),
                    )

                    observations.append({
                        "source": page["source"],
                        "url": page["url"],
                        "price": price,
                        "currency": currency,
                        "confidence": confidence,
                    })
                except Exception:
                    continue

            now = utcnow_iso()

            if not observations:
                err = (
                    "Doğrulanabilir fiyat çıkarılamadı. Site fiyatı JavaScript ile "
                    "yüklüyor veya otomatik erişimi engelliyor olabilir."
                )
                conn.execute(
                    "UPDATE trackers SET last_checked_at=?, last_error=? WHERE id=?",
                    (now, err, t["id"]),
                )
                conn.commit()
                return {"ok": False, "error": err}

            eligible = [
                o for o in observations
                if o["confidence"] >= ALERT_MIN_CONFIDENCE
            ]
            best = min(eligible or observations, key=lambda o: o["price"])
            product_name = t["product_name"] or best_title or t["query"]

            conn.execute(
                """UPDATE trackers
                   SET product_name=?, last_checked_at=?, last_price=?,
                       last_source=?, last_url=?, last_confidence=?, last_error=NULL
                   WHERE id=?""",
                (
                    product_name, now, best["price"], best["source"],
                    best["url"], best["confidence"], t["id"]
                ),
            )

            alert_state = "not_triggered"

            if best["price"] > t["target_price"]:
                conn.execute(
                    "UPDATE trackers SET last_notified_price=NULL WHERE id=?",
                    (t["id"],)
                )
            elif best["confidence"] >= ALERT_MIN_CONFIDENCE:
                should_notify = (
                    t["last_notified_price"] is None
                    or best["price"] < t["last_notified_price"]
                )

                if should_notify:
                    sent, alert_state = send_email(
                        t["email"], product_name, t["target_price"],
                        best["price"], t["currency"], best["source"],
                        best["url"], best["confidence"]
                    )

                    if sent:
                        conn.execute(
                            """UPDATE trackers
                               SET last_notified_price=?, notified_at=?
                               WHERE id=?""",
                            (best["price"], utcnow_iso(), t["id"]),
                        )

            conn.commit()
            return {
                "ok": True,
                **best,
                "observations": len(observations),
                "alert": alert_state,
            }

        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            conn.execute(
                "UPDATE trackers SET last_checked_at=?, last_error=? WHERE id=?",
                (utcnow_iso(), err, t["id"]),
            )
            conn.commit()
            return {"ok": False, "error": err}


def scheduler_loop():
    while not _stop_event.wait(CHECK_INTERVAL_MINUTES * 60):
        try:
            with db() as conn:
                ids = [
                    row["id"]
                    for row in conn.execute(
                        "SELECT id FROM trackers WHERE active=1"
                    ).fetchall()
                ]

            for tracker_id in ids:
                check_tracker(tracker_id)
        except Exception:
            pass


def start_scheduler_once():
    global _scheduler_started
    if not ENABLE_SCHEDULER:
        return

    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True
        threading.Thread(
            target=scheduler_loop,
            daemon=True,
            name="price-check-scheduler",
        ).start()


@app.get("/")
def root():
    return jsonify({
        "service": "Fiyat Alarmı API",
        "ok": True,
        "nvidia_configured": bool(NVIDIA_API_KEY),
        "scheduler_enabled": ENABLE_SCHEDULER,
    })


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/api/trackers")
def create_tracker():
    data = request.get_json(silent=True) or {}

    query = str(data.get("query", "")).strip()
    email = str(data.get("email", "")).strip()
    currency = str(data.get("currency", "TRY")).upper().strip()

    try:
        target = float(data.get("target_price"))
    except Exception:
        target = 0

    if len(query) < 2 or target <= 0 or "@" not in email:
        return jsonify({
            "error": "Ürün, hedef fiyat ve geçerli e-posta gerekli."
        }), 400

    parsed = urlparse(query)
    source_url = (
        query
        if parsed.scheme in {"http", "https"} and parsed.hostname
        else None
    )

    if source_url and not is_public_http_url(source_url):
        return jsonify({"error": "Bu URL güvenlik nedeniyle kullanılamıyor."}), 400

    tracker_id = secrets.token_hex(16)
    token = secrets.token_urlsafe(32)

    with db() as conn:
        conn.execute(
            """INSERT INTO trackers
               (id, manage_token_hash, query, source_url, target_price,
                currency, email, active, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                tracker_id,
                hash_token(token),
                query,
                source_url,
                target,
                currency,
                email,
                1,
                utcnow_iso(),
            ),
        )
        conn.commit()

    threading.Thread(
        target=check_tracker,
        args=(tracker_id,),
        daemon=True,
    ).start()

    return jsonify({
        "id": tracker_id,
        "manage_token": token,
        "status": "created",
    })


@app.get("/api/trackers/<tracker_id>")
def get_tracker(tracker_id):
    tracker, err = auth_tracker(tracker_id)
    if err:
        return err
    return jsonify(public_tracker(tracker))


@app.post("/api/trackers/<tracker_id>/check")
def manual_check(tracker_id):
    tracker, err = auth_tracker(tracker_id)
    if err:
        return err
    return jsonify(check_tracker(tracker_id))


@app.patch("/api/trackers/<tracker_id>/active")
def set_active(tracker_id):
    tracker, err = auth_tracker(tracker_id)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    active = 1 if bool(data.get("active")) else 0

    with db() as conn:
        conn.execute(
            "UPDATE trackers SET active=? WHERE id=?",
            (active, tracker_id)
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM trackers WHERE id=?",
            (tracker_id,)
        ).fetchone()

    return jsonify(public_tracker(updated))


@app.delete("/api/trackers/<tracker_id>")
def delete_tracker(tracker_id):
    tracker, err = auth_tracker(tracker_id)
    if err:
        return err

    with db() as conn:
        conn.execute(
            "DELETE FROM price_observations WHERE tracker_id=?",
            (tracker_id,)
        )
        conn.execute(
            "DELETE FROM trackers WHERE id=?",
            (tracker_id,)
        )
        conn.commit()

    return jsonify({"ok": True})


init_db()
start_scheduler_once()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
