# tests/test_security/test_ssl_context_loader.py
import sys 
import pytest
import ssl
import logging
from pathlib import Path
from app.infra.security.ssl_context_loader import create_strict_ssl_context

def test_ssl_context_creation_default():
    ctx = create_strict_ssl_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

def test_ciphers_include_expected_and_exclude_insecure():
    ctx = create_strict_ssl_context()
    cipher_names = {c["name"] for c in ctx.get_ciphers()}
    expected = {
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305"
    }
    # all expected ciphers are enabled
    assert expected.issubset(cipher_names)
    # no insecure RC4 suites
    assert all("RC4" not in name for name in cipher_names)

def test_options_disable_insecure_protocols_and_compression():
    ctx = create_strict_ssl_context()
    opts = ctx.options

    
    if sys.version_info < (3, 12):
        assert opts & ssl.OP_NO_SSLv2, "Expected OP_NO_SSLv2 to be set"
        assert opts & ssl.OP_NO_TLSv1, "Expected OP_NO_TLSv1 to be set"
        assert opts & ssl.OP_NO_TLSv1_1, "Expected OP_NO_TLSv1_1 to be set"
    else:
       
        assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2

    # בדיקה ל־NO_COMPRESSION תמיד רלוונטית
    assert opts & ssl.OP_NO_COMPRESSION, "Expected OP_NO_COMPRESSION to be set"

def test_fail_on_invalid_cafile(tmp_path, caplog):
    caplog.set_level(logging.ERROR)
    missing = tmp_path / "nope.pem"
    with pytest.raises(FileNotFoundError):
        create_strict_ssl_context(cafile=str(missing))
    assert "CA file not found" in caplog.text
