"""Email connection checker. Run:  python check_email.py

With BREVO_API_KEY set: checks the key and that EMAIL_SENDER is a verified Brevo sender.
Otherwise: tests smtp.gmail.com on ports 587 and 465 step by step.
"""
import json
import os
import urllib.error
import urllib.request
import smtplib
import socket
import ssl

BASE = os.path.dirname(os.path.abspath(__file__))
env = {}
path = os.path.join(BASE, ".env")
if os.path.exists(path):
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip("'\"")

brevo_key = env.get("BREVO_API_KEY", "").strip()
if brevo_key:
    sender = env.get("EMAIL_SENDER", "")
    print(f"Mode: Brevo API   Sender: {sender or '(missing)'}\n")
    if brevo_key.startswith("xsmtpsib"):
        print("FAIL  This is a Brevo SMTP key. Create an API key instead (SMTP & API > API Keys, starts with xkeysib).")
        raise SystemExit(1)

    def get(path):
        req = urllib.request.Request("https://api.brevo.com/v3" + path,
                                     headers={"api-key": brevo_key, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())

    try:
        acct = get("/account")
        print(f"  OK    API key works (Brevo account {acct.get('email')})")
    except urllib.error.HTTPError as e:
        print(f"  FAIL  Brevo rejected the key: HTTP {e.code} {e.read().decode(errors='ignore')[:200]}")
        raise SystemExit(1)
    except Exception as e:
        print(f"  FAIL  Could not reach api.brevo.com: {type(e).__name__}: {e}")
        raise SystemExit(1)

    try:
        senders = get("/senders").get("senders", [])
        match = [x for x in senders if x.get("email", "").lower() == sender.lower()]
        if match and match[0].get("active"):
            print(f"  OK    Sender {sender} is verified in Brevo")
            print("\nRESULT: Brevo is ready. Restart the app and send a test email from the admin page.")
        elif match:
            print(f"  FAIL  Sender {sender} is added but not verified. Click the link Brevo emailed to that address.")
        else:
            listed = ", ".join(x.get("email", "") for x in senders) or "none"
            print(f"  FAIL  {sender} is not a Brevo sender (senders on this account: {listed}).")
            print("        Add it under Senders, Domains and Dedicated IPs, or change EMAIL_SENDER to one listed.")
    except Exception as e:
        print(f"  WARN  Could not list senders ({e}); try a test email from the admin page.")
    raise SystemExit(0)

host = env.get("SMTP_HOST", "smtp.gmail.com")
user = env.get("EMAIL_SENDER", "")
pw = env.get("APP_PASS_EMAIL_PASSWORD", "").replace(" ", "")
print(f"Sender: {user or '(missing)'}   App password length: {len(pw)} (should be 16)\n")


def step(label, fn):
    try:
        out = fn()
        print(f"  OK    {label}" + (f": {out}" if out else ""))
        return True
    except Exception as exc:
        print(f"  FAIL  {label}: {type(exc).__name__}: {exc}")
        return False


try:
    ip = socket.gethostbyname(host)
    print(f"DNS: {host} -> {ip}\n")
except Exception as exc:
    print(f"DNS FAILED for {host}: {exc}\nCheck internet connection.")
    raise SystemExit(1)

results = {}
for port in (587, 465):
    print(f"Port {port}")
    ok = step("TCP connect", lambda: socket.create_connection((host, port), timeout=10).close())
    if ok:
        def full():
            ctx = ssl.create_default_context()
            if port == 465:
                s = smtplib.SMTP_SSL(host, port, timeout=15, context=ctx)
            else:
                s = smtplib.SMTP(host, port, timeout=15)
                s.ehlo()
                s.starttls(context=ctx)
                s.ehlo()
            cert = s.sock.getpeercert()
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            s.login(user, pw)
            s.quit()
            return f"certificate issued by {issuer.get('organizationName', '?')}"
        ok = step("TLS handshake and Gmail login", full)
    results[port] = ok
    print()

if any(results.values()):
    good = [p for p, ok in results.items() if ok][0]
    print(f"RESULT: email works on port {good}.")
    if good != 587:
        print(f"Set SMTP_PORT={good} in .env (the app also switches automatically).")
else:
    print("RESULT: neither port works from this PC. Most likely causes, in order:")
    print("  1. Antivirus email scanning (Avast/AVG 'Mail Shield', Kaspersky 'Mail Anti-Virus',")
    print("     Quick Heal 'Email Protection', ESET 'Email client protection'). Turn it off and retry.")
    print("  2. The network blocks mail ports (college/office WiFi). Try a mobile hotspot.")
    print("  3. A VPN or proxy is on. Turn it off and retry.")
    print("If the login step says 'Username and Password not accepted', create a new app password.")
