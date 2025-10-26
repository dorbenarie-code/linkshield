import ssl
import logging
from typing import Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def create_strict_ssl_context(cafile: Optional[str] = None) -> ssl.SSLContext:
    try:
        context = ssl.create_default_context(
            purpose=ssl.Purpose.CLIENT_AUTH,
            cafile=cafile
        )
    except FileNotFoundError:
        logger.error("CA file not found: %s", cafile)
        raise
    except ssl.SSLError as e:
        logger.error("Failed to create default SSL context: %s", e)
        raise

    # Modern TLS only
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Still good to disable compression
    context.options |= ssl.OP_NO_COMPRESSION

    cipher_suites = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305"
    ]
    try:
        context.set_ciphers(":".join(cipher_suites))
    except ssl.SSLError as e:
        logger.error("Failed to set cipher suites: %s", e)
        raise

    logger.info(
        "Created strict SSL context (minimum TLS %s) with %d cipher suites.",
        context.minimum_version.name,
        len(cipher_suites)
    )
    return context
