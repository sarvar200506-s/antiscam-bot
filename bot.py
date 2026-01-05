from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters
import re
from urllib.parse import urlparse
import whois
import requests
from datetime import datetime
import time

# ================== TOKENLAR ==================
TOKEN = "8269190292:AAHr9U65vn1ZRpTI8K5qC6lifl5D26ylW5I"
VT_API_KEY = "7a02585010978ed1ed3148a664e8a59d71ae619f786f11c3e29d18158ed3ba70"

# ================== SOZLAMALAR ==================
SUSPICIOUS_WORDS = [
    "secure", "login", "verify", "bonus", "free",
    "gift", "claim", "support", "update", "auth"
]

POPULAR_BRANDS = [
    "facebook", "paypal", "instagram", "telegram",
    "google", "apple", "binance", "meta"
]

SHORTENERS = ["bit.ly", "tinyurl", "t.co", "is.gd"]

CACHE = {}          # url -> (result, time)
CACHE_TTL = 3600    # 1 soat

# ================== YORDAMCHI ==================

def get_cached(url):
    if url in CACHE:
        result, t = CACHE[url]
        if time.time() - t < CACHE_TTL:
            return result
    return None

def set_cache(url, result):
    CACHE[url] = (result, time.time())

# ================== WHOIS ==================

def domain_age_score(domain):
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return 30, "Domen yoshi aniqlanmadi (shubhali)"

        age_days = (datetime.now() - created).days
        if age_days < 30:
            return 50, f"Domen juda yangi ({age_days} kun)"
        elif age_days < 180:
            return 25, f"Domen nisbatan yangi ({age_days} kun)"
        else:
            return 0, f"Domen yoshi: {age_days} kun"
    except:
        return 30, "WHOIS tekshiruvi muvaffaqiyatsiz (shubhali)"

# ================== VIRUSTOTAL ==================

def virustotal_score(url):
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        if r.status_code != 200:
            return 0, "VirusTotal javob bermadi"

        analysis_id = r.json()["data"]["id"]

        analysis = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        ).json()

        stats = analysis["data"]["attributes"]["stats"]
        if stats["malicious"] > 0 or stats["suspicious"] > 0:
            return 100, "VirusTotal: zararli deb belgilangan"

        return 0, "VirusTotal: zararli topilmadi"
    except:
        return 0, "VirusTotal tekshirilmadi"

# ================== ASOSIY ANALIZ ==================

def analyze_link(text: str) -> str:
    urls = re.findall(r'(https?://\S+)', text.lower())
    if not urls:
        return "🔎 Link topilmadi."

    url = urls[0]

    cached = get_cached(url)
    if cached:
        return cached

    parsed = urlparse(url)
    domain = parsed.netloc

    score = 0
    reasons = []

    if not url.startswith("https://"):
        score += 40
        reasons.append("HTTPS yo‘q")

    if any(s in domain for s in SHORTENERS):
        score += 25
        reasons.append("Qisqartirilgan link")

    suspicious_hit = any(w in domain for w in SUSPICIOUS_WORDS)
    brand_hit = any(b in domain for b in POPULAR_BRANDS)

    if suspicious_hit:
        score += 20
        reasons.append("Shubhali so‘zlar mavjud")

    if brand_hit:
        score += 20
        reasons.append("Mashhur brend nomi ishlatilgan")

    if suspicious_hit and brand_hit:
        score += 50
        reasons.append("SCAM PATTERN: brend + login/secure")

    age_score, age_reason = domain_age_score(domain)
    score += age_score
    reasons.append(age_reason)

    vt_score, vt_reason = virustotal_score(url)
    score += vt_score
    reasons.append(vt_reason)

    if score >= 60:
        status = "❌ ALDOV EHTIMOLI JUDA YUQORI"
    elif score >= 30:
        status = "⚠️ SHUBHALI LINK"
    else:
        status = "✅ NISBATAN XAVFSIZ"

    result = (
        f"{status}\n\n"
        f"🔗 Link:\n{url}\n\n"
        f"📊 Ball: {score}\n"
        f"🧠 Sabablar:\n" +
        "\n".join(f"– {r}" for r in reasons) +
        "\n\n⚠️ Tavsiya: KIRMANG, MA’LUMOT KIRITMANG"
    )

    set_cache(url, result)
    return result

# ================== TELEGRAM ==================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Salom 👋\nLink yuboring — men uni real anti-scam tizimi bilan tekshiraman 🔍"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(analyze_link(update.message.text))

# ================== ISHGA TUSHIRISH ==================

app = ApplicationBuilder().token(TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

print("Bot ishga tushdi...")
app.run_polling()
