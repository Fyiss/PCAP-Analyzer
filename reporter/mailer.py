"""
mailer.py — Sends the HTML report via email

We use Gmail SMTP with an App Password.
An App Password is a special password Google gives you
for apps — it's NOT your regular Gmail password.
It lets the script log in without needing 2FA codes.

How to get a Gmail App Password:
1. Go to myaccount.google.com
2. Security → 2-Step Verification → turn ON
3. Security → App Passwords
4. Select app: Mail, device: Other → type "pcap-analyser"
5. Copy the 16-character password into your .env file
"""

import os
import smtplib
from email.mime.multipart  import MIMEMultipart
from email.mime.text       import MIMEText
from email.mime.base       import MIMEBase
from email                 import encoders
from datetime              import datetime

# Gmail SMTP settings
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587   # TLS port

def send_report(report_path, recipient_email):
    """
    Email the HTML report as both:
    - Inline HTML body (readable directly in Gmail)
    - Attached .html file (downloadable)
    """

    # Load credentials from .env
    sender_email   = os.getenv("EMAIL_SENDER")
    sender_password = os.getenv("EMAIL_PASSWORD")

    if not sender_email or not sender_password:
        print("    [!] EMAIL_SENDER or EMAIL_PASSWORD not set in .env — skipping email")
        print(f"    [*] Report saved locally at: {report_path}")
        return False

    # Read the HTML report content
    try:
        with open(report_path, "r") as f:
            html_content = f.read()
    except Exception as e:
        print(f"    [!] Could not read report file: {e}")
        return False

    # Build the email
    now     = datetime.now().strftime("%Y-%m-%d %H:%M")
    subject = f"🔍 PCAP Analysis Report — {now}"

    msg = MIMEMultipart("mixed")
    msg["From"]    = f"PCAP Analyser <{sender_email}>"
    msg["To"]      = recipient_email
    msg["Subject"] = subject

    # --- Part 1: Plain text fallback ---
    # Some email clients can't render HTML
    plain_text = f"""PCAP Analysis Report
Generated: {now}
Tool: pcap-analyser v1.0

Please open the attached HTML file or view in an
HTML-capable email client for the full report.

-- Darshith Thalipady Nagesh
"""
    msg.attach(MIMEText(plain_text, "plain"))

    # --- Part 2: Inline HTML body ---
    msg.attach(MIMEText(html_content, "html"))

    # --- Part 3: Attached HTML file ---
    # So the recipient can save and re-open it
    try:
        with open(report_path, "rb") as f:
            attachment = MIMEBase("application", "octet-stream")
            attachment.set_payload(f.read())
            encoders.encode_base64(attachment)
            filename = os.path.basename(report_path)
            attachment.add_header(
                "Content-Disposition",
                f'attachment; filename="{filename}"'
            )
            msg.attach(attachment)
    except Exception as e:
        print(f"    [!] Could not attach file: {e}")
        # Continue anyway — inline HTML still works

    # --- Send via Gmail SMTP ---
    try:
        print(f"    [*] Connecting to {SMTP_HOST}:{SMTP_PORT}...")
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)

        # EHLO — introduce ourselves to the mail server
        server.ehlo()

        # STARTTLS — upgrade connection to encrypted TLS
        # This is why we use port 587, not 465
        server.starttls()
        server.ehlo()  # re-introduce after TLS upgrade

        print(f"    [*] Logging in as {sender_email}...")
        server.login(sender_email, sender_password)

        print(f"    [*] Sending to {recipient_email}...")
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()

        print(f"    [+] Email sent successfully to {recipient_email}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("    [!] Authentication failed.")
        print("    [!] Make sure you're using an App Password, not your Gmail password.")
        print("    [!] Get one at: myaccount.google.com → Security → App Passwords")
        return False

    except smtplib.SMTPException as e:
        print(f"    [!] SMTP error: {e}")
        return False

    except Exception as e:
        print(f"    [!] Unexpected error sending email: {e}")
        return False
