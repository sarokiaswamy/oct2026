"""Real email sending: Brevo HTTPS API when BREVO_API_KEY is set, otherwise SMTP (Gmail).

Brevo goes over port 443 (normal HTTPS), so it works on networks and PCs that
block mail ports 587/465.

Emails are queued and sent by a background thread, so a slow mail server
never blocks billing, disconnection or payment.
"""
import json
import logging
import queue
import smtplib
import ssl
import threading
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

log = logging.getLogger("gridpay.mail")


class Mailer:
    def __init__(self, sender, password, host="smtp.gmail.com", port=587,
                 from_name="GridPay Billing", on_result=None, brevo_key=""):
        self.brevo_key = (brevo_key or "").strip()
        self.sender = (sender or "").strip()
        # Gmail shows app passwords in groups of four; spaces are not part of it
        self.password = (password or "").replace(" ", "").strip()
        self.host = host
        self.port = int(port)
        self.from_name = from_name
        self.on_result = on_result
        self._queue = queue.Queue()
        self._worker = None

    @property
    def transport(self):
        return "Brevo API" if self.brevo_key else "Gmail SMTP"

    @property
    def configured(self):
        return bool(self.sender and (self.brevo_key or self.password))

    def start(self):
        if self._worker is None:
            self._worker = threading.Thread(target=self._run, name="mailer", daemon=True)
            self._worker.start()

    def send_async(self, to, subject, text, html, kind="notice"):
        """Queue an email. Returns immediately."""
        if not to:
            return
        if not self.configured:
            self._report(to, subject, kind, False, "Email not configured (set EMAIL_SENDER and BREVO_API_KEY or APP_PASS_EMAIL_PASSWORD in .env)")
            return
        self._queue.put((to, subject, text, html, kind))

    def send_now(self, to, subject, text, html, kind="test"):
        """Send immediately and return (ok, error). Used for the test button."""
        if not self.configured:
            err = "Email not configured (set EMAIL_SENDER and BREVO_API_KEY or APP_PASS_EMAIL_PASSWORD in .env)"
            self._report(to, subject, kind, False, err)
            return False, err
        ok, err = self._deliver(to, subject, text, html)
        self._report(to, subject, kind, ok, err)
        return ok, err

    # ------------------------------------------------------------------
    def _run(self):
        while True:
            to, subject, text, html, kind = self._queue.get()
            ok, err = self._deliver(to, subject, text, html)
            if not ok:  # one retry for temporary network hiccups
                ok, err = self._deliver(to, subject, text, html)
            self._report(to, subject, kind, ok, err)

    def _deliver(self, to, subject, text, html):
        if self.brevo_key:
            return self._deliver_brevo(to, subject, text, html)
        return self._deliver_smtp(to, subject, text, html)

    def _deliver_brevo(self, to, subject, text, html):
        if self.brevo_key.startswith("xsmtpsib"):
            return False, ("BREVO_API_KEY holds an SMTP key. In Brevo go to SMTP & API, open the API Keys tab "
                           "and create an API key (it starts with xkeysib).")
        body = json.dumps({
            "sender": {"name": self.from_name, "email": self.sender},
            "to": [{"email": to}],
            "subject": subject,
            "htmlContent": html,
            "textContent": text,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.brevo.com/v3/smtp/email", data=body, method="POST",
            headers={"api-key": self.brevo_key, "Content-Type": "application/json",
                     "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                info = json.loads(resp.read() or b"{}")
            log.info("Email sent to %s via Brevo (%s): %s", to, info.get("messageId"), subject)
            return True, None
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read()).get("message", "")
            except Exception:
                detail = ""
            if exc.code == 401:
                return False, f"Brevo rejected the API key ({detail or 'unauthorized'}). Copy the key again from Brevo."
            if exc.code == 400 and "sender" in detail.lower():
                return False, (f"Brevo says the sender {self.sender} is not verified: {detail}. "
                               "Verify it under Senders, Domains and Dedicated IPs.")
            return False, f"Brevo error {exc.code}: {detail or exc.reason}"
        except ssl.SSLError as exc:
            return False, f"HTTPS certificate problem reaching Brevo ({exc}). Antivirus HTTPS scanning can cause this."
        except (OSError, urllib.error.URLError) as exc:
            return False, f"Could not reach api.brevo.com: {exc}"

    def _deliver_smtp(self, to, subject, text, html):
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = formataddr((self.from_name, self.sender))
        msg["To"] = to
        msg["Message-ID"] = make_msgid(domain=self.sender.split("@")[-1] or None)
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")

        # Try the configured port first; if the connection is cut (antivirus mail
        # shield, network blocking 587), fall back to the other Gmail port.
        ports = [self.port] + [p for p in (587, 465) if p != self.port]
        errors = []
        for port in ports:
            try:
                self._send_via(port, msg)
                if port != self.port:
                    log.info("Port %s worked, using it from now on", port)
                    self.port = port
                log.info("Email sent to %s via port %s: %s", to, port, subject)
                return True, None
            except smtplib.SMTPAuthenticationError:
                return False, ("Gmail rejected the login. Check EMAIL_SENDER and the 16 character app password, "
                               "and that 2-Step Verification is on for that account.")
            except (OSError, smtplib.SMTPException) as exc:
                log.warning("Port %s failed for %s: %s", port, to, exc)
                errors.append(f"port {port}: {type(exc).__name__}: {exc}")
        return False, ("Could not reach the mail server (" + "; ".join(errors) + "). "
                       "Usually antivirus email scanning or the network is blocking mail ports. "
                       "Run python check_email.py for details.")

    def _send_via(self, port, msg):
        context = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(self.host, port, timeout=20, context=context) as s:
                s.login(self.sender, self.password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(self.host, port, timeout=20) as s:
                s.ehlo()
                s.starttls(context=context)
                s.ehlo()
                s.login(self.sender, self.password)
                s.send_message(msg)

    def _report(self, to, subject, kind, ok, err):
        if self.on_result:
            try:
                self.on_result(to, subject, kind, ok, err)
            except Exception:
                log.exception("Email result callback failed")
