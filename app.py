import os
import re
import secrets
from flask import Flask, request, session, redirect, url_for, render_template

# -----------------------
# Config
# -----------------------
class Config:
    # set SECRET_KEY in env for production, fallback to random for demo
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(16)
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME") or "admin"
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "admin123"  # Change before deploy

# -----------------------
# Flask App
# -----------------------
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config["SECRET_KEY"]

# -----------------------
# Detection Functions (simple regex filters)
# -----------------------
def detect_suspicious_urls(text):
    urls = re.findall(r"https?://[^\s'\"<>]+", text, re.IGNORECASE)
    suspicious = []
    for url in urls:
        lower = url.lower()
        # keywords that often appear in phishing urls
        if re.search(r"(login|verify|secure|update|account|bank|confirm|signin)", lower):
            suspicious.append(url)
            continue
        # many subdomains like a.b.c.example.com can be suspicious
        domain_part = re.sub(r"^https?://", "", lower).split("/")[0]
        if domain_part.count(".") >= 3:
            suspicious.append(url)
    return suspicious

def detect_urgent_words(text):
    urgent_keywords = ["urgent", "immediately", "verify", "verify now", "suspend",
                       "password", "login", "action required", "click here", "limited time"]
    found = [kw for kw in urgent_keywords if re.search(rf"\b{re.escape(kw)}\b", text, re.IGNORECASE)]
    return list(dict.fromkeys(found))

def detect_suspicious_sender(text):
    m = re.search(r'From:\s*(?:".+?"\s*)?<([^>]+)>', text, re.IGNORECASE)
    if not m:
        return None
    sender = m.group(1).strip()
    if "@" not in sender:
        return sender
    domain = sender.split("@", 1)[1].lower()
    if re.search(r"(secure|verify|login|update|account|service|support[\-_])", domain):
        return sender
    if domain.count("-") >= 2:
        return sender
    return None

def detect_attachments(text):
    # return list of suspicious file names (exe, zip, js, etc.)
    return re.findall(r"\b([\w\-. ]+\.(?:exe|scr|zip|rar|js|vbs|bat|cmd|msi))\b", text, re.IGNORECASE)

def detect_reply_to_mismatch(text):
    from_match = re.search(r'From:\s*(?:".+?"\s*)?<([^>]+)>', text, re.IGNORECASE)
    reply_match = re.search(r'Reply-To:\s*(?:".+?"\s*)?<([^>]+)>', text, re.IGNORECASE)
    if from_match and reply_match:
        from_addr = from_match.group(1).strip()
        reply_addr = reply_match.group(1).strip()
        try:
            if from_addr.split("@",1)[1].lower() != reply_addr.split("@",1)[1].lower():
                return (from_addr, reply_addr)
        except Exception:
            return (from_addr, reply_addr)
    return None

# -----------------------
# Routes
# -----------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if username == app.config["ADMIN_USERNAME"] and password == app.config["ADMIN_PASSWORD"]:
            session["user"] = username
            return redirect(url_for("detector"))
        else:
            error = "Invalid username or password"
            return render_template("login.html", error=error)
    # GET
    if "user" in session:
        return redirect(url_for("detector"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route("/detector", methods=["GET", "POST"])
def detector():
    if "user" not in session:
        return redirect(url_for("login"))

    result = None
    sample = ""
    if request.method == "POST":
        email_text = request.form.get("email", "")
        sample = email_text
        flags = []
        score = 0

        urls = detect_suspicious_urls(email_text)
        if urls:
            flags.append({"title":"Suspicious URLs","desc":", ".join(urls),"points":2})
            score += 2

        urgent = detect_urgent_words(email_text)
        if urgent:
            flags.append({"title":"Urgent Language","desc":", ".join(urgent),"points":1})
            score += 1

        sus_sender = detect_suspicious_sender(email_text)
        if sus_sender:
            flags.append({"title":"Suspicious Sender","desc":sus_sender,"points":2})
            score += 2

        attach = detect_attachments(email_text)
        if attach:
            flags.append({"title":"Suspicious Attachment","desc":", ".join(attach),"points":2})
            score += 2

        reply_m = detect_reply_to_mismatch(email_text)
        if reply_m:
            from_addr, reply_addr = reply_m
            flags.append({"title":"Reply-To Mismatch","desc":f"From: {from_addr} | Reply-To: {reply_addr}","points":1})
            score += 1

        risk = "LOW" if score < 3 else "MEDIUM" if score < 6 else "HIGH"
        result = {
            "score": score,
            "risk": risk,
            "flags": flags,
            "tips": [
                "Hover links to see the real address before clicking.",
                "Check the sender and Reply-To domains.",
                "Be careful with urgent requests to login/update.",
                "Never run suspicious attachments.",
                "Open official website directly instead of clicking links."
            ]
        }

    return render_template("detector.html", result=result, sample=sample)

# -----------------------
# Run App
# -----------------------
if __name__ == "__main__":
    # debug True only for local development
    app.run(host="0.0.0.0", port=5000, debug=True)
