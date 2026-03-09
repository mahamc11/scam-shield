import math
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

try:
    from langdetect import detect
except Exception:  # optional dependency
    detect = None

try:
    from deep_translator import GoogleTranslator
except Exception:  # optional dependency
    GoogleTranslator = None


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "scamshield.db"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {
    "mp3", "wav", "m4a", "ogg", "aac",  # audio
    "png", "jpg", "jpeg", "webp", "gif",  # images
    "pdf", "doc", "docx", "txt",  # docs
}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            company_name TEXT,
            company_address TEXT,
            phone_number TEXT,
            original_text TEXT,
            translated_text TEXT,
            score REAL,
            label TEXT,
            explanation TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    conn.commit()
    conn.close()


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def translate_to_english(text: str):
    """Translate arbitrary-language text to English when translator is available."""
    if not text.strip():
        return "", "No input"

    language = "unknown"
    if detect:
        try:
            language = detect(text)
        except Exception:
            language = "unknown"

    if GoogleTranslator is None:
        return text, f"Translation service unavailable; using original text (detected={language})."

    try:
        translated = GoogleTranslator(source="auto", target="en").translate(text)
        return translated, f"Auto-translated to English (detected={language})."
    except Exception:
        return text, f"Translation failed; using original text (detected={language})."


def normalize_text(text: str) -> str:
    text = (text or "").lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_domains(text: str):
    urls = re.findall(r"https?://[^\s]+", text)
    domains = []
    for url in urls:
        try:
            domains.append(urlparse(url).netloc.lower().replace("www.", ""))
        except Exception:
            pass

    # Also catch raw domain patterns in text
    raw = re.findall(r"\b([a-z0-9-]+\.(?:com|in|org|net|co|io|biz|info))\b", text)
    domains.extend(raw)
    return sorted(set([d for d in domains if d]))


def analyze_text_signals(text: str):
    """Weighted NLP-style heuristics with richer pattern coverage."""
    lower = normalize_text(text)

    weighted_phrases = {
        "advance_fee": {
            "weight": 22,
            "patterns": [
                "registration fee", "processing fee", "security deposit", "training fee",
                "pay first", "payment before joining", "pay to confirm", "unrefundable",
            ],
        },
        "urgency_pressure": {
            "weight": 12,
            "patterns": ["urgent", "immediately", "today only", "act now", "limited slots", "within 1 hour"],
        },
        "too_good_to_be_true": {
            "weight": 16,
            "patterns": ["high salary", "easy money", "guaranteed job", "no interview", "earn daily", "work 1 hour"],
        },
        "off_platform_or_private_channel": {
            "weight": 12,
            "patterns": ["whatsapp only", "telegram", "dm me", "personal number", "private chat"],
        },
        "sensitive_data_request": {
            "weight": 16,
            "patterns": ["otp", "bank details", "aadhar", "passport", "cvv", "upi pin"],
        },
        "threat_or_penalty": {
            "weight": 12,
            "patterns": ["account will be blocked", "penalty", "legal action", "last warning"],
        },
    }

    score = 0.0
    factors = []
    for factor, config in weighted_phrases.items():
        hits = [p for p in config["patterns"] if p in lower]
        if hits:
            increment = min(config["weight"], 6 + 4 * len(hits))
            score += increment
            factors.append((factor, hits, round(increment, 2)))

    # Structural markers
    exclamations = text.count("!")
    if exclamations >= 3:
        score += 4
        factors.append(("aggressive_punctuation", ["multiple exclamation marks"], 4))

    caps_words = re.findall(r"\b[A-Z]{4,}\b", text)
    if len(caps_words) >= 4:
        score += 4
        factors.append(("overuse_caps", ["multiple all-caps words"], 4))

    # Suspicious contact patterns
    personal_email_domains = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "protonmail.com"}
    email_domains = re.findall(r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text)
    if email_domains and any(d.lower() in personal_email_domains for d in email_domains):
        score += 8
        factors.append(("non_corporate_email", list(set(email_domains)), 8))

    domains = extract_domains(text)
    if any("bit.ly" in d or "tinyurl" in d for d in domains):
        score += 10
        factors.append(("shortened_links", domains, 10))

    return min(score, 70), factors


def analyze_legitimacy_signals(text: str, company_name: str):
    """Find positive trust indicators to reduce false positives."""
    lower = normalize_text(text)
    score = 0
    notes = []

    positive_phrases = [
        "official website", "career page", "linkedin company page", "glassdoor reviews",
        "formal interview", "hr round", "technical round", "offer letter on company letterhead",
        "no registration fee", "do not pay", "background verification",
    ]
    hits = [p for p in positive_phrases if p in lower]
    if hits:
        gain = min(20, 4 + len(hits) * 2)
        score += gain
        notes.append(f"Legitimacy indicators found ({', '.join(hits[:5])}) -{gain}")

    # Corporate email/domain consistency can lower risk a bit
    domains = extract_domains(text)
    tokens = [t for t in re.split(r"[^a-z0-9]+", (company_name or '').lower()) if len(t) >= 4]
    if domains and tokens and any(any(t in d for t in tokens) for d in domains):
        score += 8
        notes.append("Shared domain appears consistent with company name -8")

    # Presence of clear process details is usually safer
    if any(k in lower for k in ["job description", "location", "ctc", "reporting manager", "notice period"]):
        score += 5
        notes.append("Detailed hiring process information present -5")

    return min(score, 30), notes


def check_phone_number(phone: str):
    """Improved heuristic phone fraud check."""
    digits = re.sub(r"\D", "", phone or "")

    score = 0
    reasons = []
    if len(digits) < 8 or len(digits) > 15:
        score += 16
        reasons.append("Invalid international length")

    if re.fullmatch(r"(\d)\1{7,}", digits or ""):
        score += 18
        reasons.append("Repeated digit pattern")

    if digits in {"1234567890", "0000000000", "9999999999", "1111111111"}:
        score += 20
        reasons.append("Known frequently reported scam pattern")

    # Detect sequential patterns like 12345678 or 987654321
    if digits and (digits in "01234567890123456789" or digits in "98765432109876543210"):
        score += 10
        reasons.append("Sequential number pattern")

    if digits.startswith("000") or digits.startswith("99999"):
        score += 10
        reasons.append("Unusual prefix")

    status = "Verified" if score < 20 else "Suspicious"
    return min(score, 45), reasons, status


def verify_company(company_name: str, company_address: str, text: str):
    """Simulated company verification with consistency checks across signals."""
    name = (company_name or "").strip()
    address = (company_address or "").strip()
    merged_text = text or ""

    score = 0
    notes = []

    if len(name) < 3:
        score += 20
        notes.append("Company name too short/incomplete")

    risky_tokens = ["crypto", "quick cash", "double income", "part time instant", "limited seat"]
    if any(tok in name.lower() for tok in risky_tokens):
        score += 14
        notes.append("Company name contains high-risk wording")

    if len(address) < 8:
        score += 12
        notes.append("Company address appears incomplete")

    # Cross-check text domain branding against company name tokens.
    domains = extract_domains(merged_text)
    name_tokens = [t for t in re.split(r"[^a-z0-9]+", name.lower()) if len(t) >= 4]
    if domains and name_tokens:
        if not any(any(tok in domain for tok in name_tokens) for domain in domains):
            score += 10
            notes.append("Shared link domains do not resemble company name")

    linked_in = "Likely Found" if score < 18 else "Not Confident"
    google_maps = "Likely Found" if len(address) >= 8 else "Not Found"
    glassdoor = "Likely Found" if len(name) >= 4 else "Not Found"

    # If two+ sources are weak, bump risk.
    weak = sum(1 for s in [linked_in, google_maps, glassdoor] if s in {"Not Found", "Not Confident"})
    if weak >= 2:
        score += 8
        notes.append("Multiple public-source verifications appear weak")

    verification = {
        "LinkedIn": linked_in,
        "Google Maps": google_maps,
        "Glassdoor": glassdoor,
    }
    status = "Verified" if score < 20 else "Needs Review"
    return min(score, 45), notes, status, verification


def analyze_files(uploaded_files):
    score = 0
    notes = []
    saved = []
    for file in uploaded_files:
        if not file or not file.filename:
            continue
        if not allowed_file(file.filename):
            notes.append(f"Unsupported file ignored: {file.filename}")
            continue

        filename = secure_filename(file.filename)
        timestamped = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{filename}"
        dest = UPLOAD_DIR / timestamped
        file.save(dest)
        saved.append(timestamped)

        ext = filename.rsplit(".", 1)[1].lower()
        if ext in {"txt", "doc", "docx", "pdf"}:
            notes.append(f"Document evidence submitted: {filename}")
        if ext in {"png", "jpg", "jpeg", "webp", "gif"}:
            notes.append(f"Image evidence submitted: {filename}")
        if ext in {"mp3", "wav", "m4a", "ogg", "aac"}:
            notes.append(f"Audio evidence submitted: {filename}")

    if not saved:
        notes.append("No evidence files uploaded")
    return score, notes, saved


def combine_scores(text_score, phone_score, company_score, file_score, legitimacy_score):
    """Non-linear risk fusion: higher individual risk gets amplified."""
    weighted_sum = (0.42 * text_score) + (0.24 * phone_score) + (0.30 * company_score) + (0.04 * file_score) - (0.28 * legitimacy_score)

    # Amplify if multiple major channels are high-risk.
    channels_high = sum(1 for s in [text_score, phone_score, company_score] if s >= 25)
    if channels_high >= 2:
        weighted_sum += 8

    # Logistic squeeze to 0-100 for stable thresholds.
    risk = 100 / (1 + math.exp(-0.08 * (weighted_sum - 28)))
    return round(max(0, min(risk, 100)), 2)


def estimate_confidence(text: str, phone: str, files_count: int):
    """Confidence indicates evidence sufficiency, not guaranteed truth."""
    evidence_points = 0
    if len((text or "").strip()) >= 30:
        evidence_points += 35
    if len(re.sub(r"\D", "", phone or "")) >= 8:
        evidence_points += 30
    evidence_points += min(files_count * 15, 35)
    return min(evidence_points, 95)


def classify(score: float):
    if score >= 75:
        return "Scam"
    if score >= 45:
        return "Suspicious"
    return "Likely Genuine"


def login_required():
    return "user_id" in session


@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not (name and email and password):
            flash("Please complete all fields.", "error")
            return redirect(url_for("register"))

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, generate_password_hash(password), datetime.utcnow().isoformat()),
            )
            conn.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already exists.", "error")
            return redirect(url_for("register"))
        finally:
            conn.close()

    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        return redirect(url_for("dashboard"))

    return render_template("auth.html", mode="login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))
    return render_template("dashboard.html", result=None)


@app.route("/detect", methods=["POST"])
def detect_scam():
    if not login_required():
        return redirect(url_for("login"))

    company_name = request.form.get("company_name", "")
    company_address = request.form.get("company_address", "")
    description = request.form.get("description", "")
    phone_number = request.form.get("phone_number", "")
    voice_text = request.form.get("voice_text", "")

    merged_text = " ".join([description, voice_text]).strip()
    translated_text, translation_note = translate_to_english(merged_text)

    text_score, text_factors = analyze_text_signals(translated_text)
    legitimacy_score, legitimacy_notes = analyze_legitimacy_signals(translated_text, company_name)
    phone_score, phone_reasons, phone_status = check_phone_number(phone_number)
    company_score, company_notes, company_status, sources = verify_company(
        company_name, company_address, translated_text
    )
    file_score, file_notes, saved_files = analyze_files(request.files.getlist("evidence_files"))

    total_score = combine_scores(text_score, phone_score, company_score, file_score, legitimacy_score)
    confidence = estimate_confidence(translated_text, phone_number, len(saved_files))
    label = classify(total_score)

    reasoning = [
        f"Translation: {translation_note}",
        f"Text signal risk: {round(text_score, 2)}/70",
        f"Phone signal risk: {round(phone_score, 2)}/45",
        f"Company verification risk: {round(company_score, 2)}/45",
        f"Legitimacy offset: -{round(legitimacy_score, 2)}/30",
        f"Final fused risk score: {total_score}%",
        f"Analysis confidence (evidence sufficiency): {confidence}%",
        "Important: no automated detector can guarantee 100% accuracy; always perform manual verification.",
    ]
    if text_factors:
        for factor, matches, increment in text_factors:
            reasoning.append(f"Detected {factor} indicators ({', '.join(matches)}) +{increment}")
    if phone_reasons:
        reasoning.append("Phone findings: " + "; ".join(phone_reasons))
    if company_notes:
        reasoning.append("Company findings: " + "; ".join(company_notes))
    if legitimacy_notes:
        reasoning.append("Legitimacy findings: " + "; ".join(legitimacy_notes))
    reasoning.extend(file_notes)

    conn = get_db()
    conn.execute(
        """
        INSERT INTO detections (
            user_id, company_name, company_address, phone_number,
            original_text, translated_text, score, label, explanation, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session["user_id"],
            company_name,
            company_address,
            phone_number,
            merged_text,
            translated_text,
            total_score,
            label,
            " | ".join(reasoning),
            datetime.utcnow().isoformat(),
        ),
    )
    conn.commit()
    conn.close()

    risk_factors = {
        "Text Risk": round(text_score, 2),
        "Phone Risk": round(phone_score, 2),
        "Company Risk": round(company_score, 2),
        "Legitimacy Offset": -round(legitimacy_score, 2),
        "File Risk": round(file_score, 2),
    }

    result = {
        "label": label,
        "score": round(total_score, 2),
        "confidence": confidence,
        "explanation": reasoning,
        "risk_factors": risk_factors,
        "phone_status": phone_status,
        "company_status": company_status,
        "sources": sources,
        "uploaded_files": saved_files,
    }

    return render_template("dashboard.html", result=result)


@app.route('/chat', methods=['POST'])
def chat():
    if not login_required():
        return jsonify({"reply": "Please log in to use the assistant."}), 401

    message = (request.json or {}).get("message", "").lower().strip()
    tips = [
        "Never pay registration or processing fees for a job offer.",
        "Verify email domains. Genuine companies use official domains, not random free emails.",
        "Cross-check company name/address on LinkedIn, Google Maps, and Glassdoor.",
        "Avoid sharing OTP, bank details, or sensitive IDs early in the process.",
        "Be cautious of urgent offers with unusually high salary and no interview.",
    ]

    if any(k in message for k in ["fee", "payment", "money"]):
        reply = tips[0]
    elif any(k in message for k in ["email", "domain"]):
        reply = tips[1]
    elif any(k in message for k in ["verify", "company", "authentic"]):
        reply = tips[2]
    elif any(k in message for k in ["otp", "bank", "id"]):
        reply = tips[3]
    else:
        reply = "Here are safe practices: " + " ".join(tips[:3])

    return jsonify({"reply": reply})


init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
