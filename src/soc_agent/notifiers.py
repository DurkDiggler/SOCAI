from __future__ import annotations
import smtplib
from email.message import EmailMessage
from typing import Tuple
from .config import SETTINGS

def send_email(subject: str, body: str, subtype: str = "plain") -> Tuple[bool, str]:
    if not SETTINGS.enable_email:
        return False, "Email disabled"
    if not (SETTINGS.smtp_host and SETTINGS.email_from and SETTINGS.email_to):
        return False, "Email not configured"

    msg = EmailMessage()
    msg["From"] = SETTINGS.email_from
    msg["To"] = ", ".join(SETTINGS.email_to)
    msg["Subject"] = subject
    msg.set_content(body, subtype=subtype)

    try:
        with smtplib.SMTP(SETTINGS.smtp_host, SETTINGS.smtp_port, timeout=10) as s:
            s.starttls()
            if SETTINGS.smtp_username and SETTINGS.smtp_password:
                s.login(SETTINGS.smtp_username, SETTINGS.smtp_password)
            s.send_message(msg)
        return True, "sent"
    except Exception as exc:
        return False, str(exc)
