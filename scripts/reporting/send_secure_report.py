import logging
from pathlib import Path
from email.message import EmailMessage
from smtplib import SMTP_SSL
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

def load_key(path: Path) -> bytes:
    return path.read_bytes()

def decrypt_password(key_path: Path, pwd_path: Path) -> str:
    key = load_key(key_path)
    encrypted = pwd_path.read_bytes()
    return Fernet(key).decrypt(encrypted).decode()

def build_email(sender: str, recipient: str, subject: str, body: str, attachment: Path) -> EmailMessage:
    msg = EmailMessage()
    msg['From'], msg['To'], msg['Subject'] = sender, recipient, subject
    msg.set_content(body)
    data = attachment.read_bytes()
    msg.add_attachment(data, maintype='text', subtype='html', filename=attachment.name)
    return msg

def send_email(msg: EmailMessage, server: str, port: int, user: str, pwd: str):
    with SMTP_SSL(server, port) as smtp:
        smtp.login(user, pwd)
        smtp.send_message(msg)
    logging.info("✅ Secure email sent successfully.")

def main():
    key_file    = Path('secret.key')
    pwd_file    = Path('password.encrypted')
    report_file = Path('reports/full_test_report_2025-05-15_21-11-19.html')

    sender    = "dormahalal@gmail.com"
    recipient = "dormahalal@gmail.com"
    subject   = "📊 LinkScanner Test Report"
    body      = "Attached is the latest test report from LinkShield."

    password = decrypt_password(key_file, pwd_file)
    email_msg = build_email(sender, recipient, subject, body, report_file)
    send_email(email_msg, "smtp.gmail.com", 465, sender, password)

if __name__ == '__main__':
    main()
