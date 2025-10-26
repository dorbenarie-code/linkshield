import os
import logging
import mimetypes
import smtplib
from pathlib import Path
from dataclasses import dataclass
from email.message import EmailMessage
from dotenv import load_dotenv

# 1. Load .env once at module import
load_dotenv()

# 2. Logger setup
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@dataclass
class SMTPConfig:
    """Holds SMTP connection settings."""
    host: str
    port: int
    user: str
    password: str


def load_smtp_config() -> SMTPConfig:
    """
    Read SMTP settings from environment.
    Raises EnvironmentError if any required var is missing.
    """
    try:
        host = os.environ["SMTP_HOST"]
        port = int(os.environ.get("SMTP_PORT", "465"))
        user = os.environ["EMAIL_ADDRESS"]
        password = os.environ["EMAIL_PASSWORD"]
    except KeyError as e:
        raise EnvironmentError(f"Missing environment variable: {e}") from None

    return SMTPConfig(host, port, user, password)


def build_email(subject: str, body: str, from_addr: str, to_addr: str) -> EmailMessage:
    """
    Create an EmailMessage object with the given metadata and plain-text body.
    """
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def attach_file(msg: EmailMessage, attachment_path: Path) -> None:
    """
    Attach a file (reports/custom_report.html) to the given EmailMessage.
    Raises FileNotFoundError if the path does not exist.
    """
    if not attachment_path.exists():
        raise FileNotFoundError(f"Attachment not found: {attachment_path}")

    mime_type, _ = mimetypes.guess_type(attachment_path.name)
    maintype, subtype = (mime_type or "application/octet-stream").split("/", 1)
    data = attachment_path.read_bytes()

    msg.add_attachment(
        data,
        maintype=maintype,
        subtype=subtype,
        filename=attachment_path.name
    )
    logger.info(f"📎 Attached file: {attachment_path.name}")


class EmailSender:
    """
    Responsible for connecting to SMTP over SSL and sending the message.
    """
    def __init__(self, config: SMTPConfig):
        self.config = config

    def send(self, message: EmailMessage) -> None:
        """Login and send the email, logging success or failure."""
        try:
            with smtplib.SMTP_SSL(self.config.host, self.config.port) as server:
                server.login(self.config.user, self.config.password)
                server.send_message(message)
                logger.info(f"✅ Email sent to {message['To']}")
        except Exception as e:
            logger.error(f"❌ Failed to send email: {e}")
            raise


def send_report_email(
    subject: str,
    body: str,
    to_email: str,
    attachment: Path
) -> None:
    """
    High-level entry point: load config, build message, attach report, and send.
    Logs and suppresses known configuration issues.
    """
    try:
        config = load_smtp_config()
    except EnvironmentError as e:
        logger.warning(f"⚠️ Skipping email: {e}")
        return

    try:
        msg = build_email(subject, body, config.user, to_email)
        attach_file(msg, attachment)
        EmailSender(config).send(msg)
    except Exception as e:
        logger.error(f"❌ Failed to send report email: {e}")

