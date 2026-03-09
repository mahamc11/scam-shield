import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path

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

    # If translation dependency is unavailable, gracefully use original text.
    if GoogleTranslator is None:
        return text, f"Translation service unavailable; using original text (detected={language})."

    try:
        translated = GoogleTranslator(source="auto", target="en").translate(text)
        return translated, f"Auto-translated to English (detected={language})."
    except Exception:
        return text, f"Translation failed; using original text (detected={language})."


def analyze_text_signals(text: str):
    """Simple NLP-style heuristic scoring using scam trigger keywords."""
    lower = text.lower()
    triggers = {
        "payment": ["registration fee", "processing fee", "pay first", "deposit"],
        "urgency": ["urgent", "immediately", "today only", "limited slots"],
        "too_good": ["high salary", "easy money", "no interview", "guaranteed job"],
        "off_platform": ["whatsapp only", "telegram", "personal number", "dm me"],
        "identity_risk": ["aadhar", "passport", "bank details", "otp"],
    }

    score = 0
    factors = []
    for factor, words in triggers.items():
        matches = [w for w in words if w in lower]
        if matches:
            increment = min(18, 6 * len(matches))
            score += increment
            factors.append((factor, matches, increment))

    return min(score, 60), factors


def check_phone_number(phone: str):
    """Heuristic phone fraud check."""
    digits = re.sub(r"\D", "", phone or "")
    suspicious_patterns = {
        "repeated_digit_pattern": bool(re.fullmatch(r"(\d)\1{7,}", digits)),
        "very_short_or_long": len(digits) < 8 or len(digits) > 15,
        "starts_with_unusual_prefix": digits.startswith("000") or digits.startswith("99999"),
    }

    known_reported = {
        "1800123456", "9999999999", "1234567890", "0000000000"
    }

    score = 0
    reasons = []
    for key, is_bad in suspicious_patterns.items():
        if is_bad:
            score += 12
            reasons.append(key.replace("_", " "))

    if digits in known_reported:
        score += 25
        reasons.append("Found in frequently reported scam numbers")

    status = "Verified" if score < 20 else "Suspicious"
    return min(score, 40), reasons, status


def verify_company(company_name: str, company_address: str):
    """Simulate external verification against LinkedIn/Maps/Glassdoor."""
    name = (company_name or "").strip()
    address = (company_address or "").strip()

    score = 0
    notes = []

    if len(name) < 3:
        score += 20
        notes.append("Company name too short/incomplete")

    if any(bad in name.lower() for bad in ["crypto", "double income", "quick cash"]):
        score += 18
        notes.append("Name contains high-risk wording")

    if not address or len(address) < 8:
        score += 10
        notes.append("Company address seems incomplete")

    linked_in = "Likely Found" if score < 18 else "Not Confident"
    google_maps = "Likely Found" if len(address) >= 8 else "Not Found"
    glassdoor = "Likely Found" if len(name) >= 4 else "Not Found"

    verification = {
        "LinkedIn": linked_in,
        "Google Maps": google_maps,
        "Glassdoor": glassdoor,
    }
    status = "Verified" if score < 20 else "Needs Review"
    return min(score, 35), notes, status, verification


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
            notes.append(f"Document submitted: {filename}")
        if ext in {"png", "jpg", "jpeg", "webp", "gif"}:
            notes.append(f"Image evidence submitted: {filename}")
        if ext in {"mp3", "wav", "m4a", "ogg", "aac"}:
            notes.append(f"Audio evidence submitted: {filename}")

    if not saved:
        notes.append("No evidence files uploaded")
    return score, notes, saved


def classify(score: float):
    if score >= 70:
        return "Scam"
    if score >= 40:
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
    phone_score, phone_reasons, phone_status = check_phone_number(phone_number)
    company_score, company_notes, company_status, sources = verify_company(company_name, company_address)
    file_score, file_notes, saved_files = analyze_files(request.files.getlist("evidence_files"))

    total_score = min(text_score + phone_score + company_score + file_score, 100)
    label = classify(total_score)

    reasoning = [
        f"Translation: {translation_note}",
        f"Text signal score: {text_score}/60",
        f"Phone signal score: {phone_score}/40",
        f"Company verification score: {company_score}/35",
    ]
    if text_factors:
        for factor, matches, increment in text_factors:
            reasoning.append(f"Detected {factor} keywords ({', '.join(matches)}) +{increment}")
    if phone_reasons:
        reasoning.append("Phone findings: " + "; ".join(phone_reasons))
    if company_notes:
        reasoning.append("Company findings: " + "; ".join(company_notes))
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
        "Text Risk": text_score,
        "Phone Risk": phone_score,
        "Company Risk": company_score,
        "File Risk": file_score,
    }

    result = {
        "label": label,
        "score": round(total_score, 2),
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
