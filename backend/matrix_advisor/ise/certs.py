"""Certificates for the ISE connections: pxGrid client certificate (generated or uploaded) and the
ISE certificate chain used to verify the PAN and the pxGrid nodes.

Files live under ``<data>/certs`` (next to config.yaml). Private keys are written with mode 0600
and never leave the server: the API only returns paths and certificate details.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ..i18n import Message


class CertError(Exception):
    pass


def certs_dir(config_path: Path) -> Path:
    d = Path(config_path).parent / "certs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now() -> datetime:
    return datetime.now(UTC)


def _stamp() -> str:
    return _now().strftime("%Y%m%d-%H%M%S")


def _fingerprint(cert: x509.Certificate) -> str:
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def describe(cert: x509.Certificate) -> dict:
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    not_after = cert.not_valid_after_utc
    return {
        "subject": cn[0].value if cn else cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_signed": cert.issuer == cert.subject,
        "not_after": not_after.replace(tzinfo=None).isoformat(),
        "days_left": (not_after - _now()).days,
        "sha256": _fingerprint(cert),
    }


def load_certs(data: bytes) -> list[x509.Certificate]:
    """PEM (one or several certificates) or a single DER certificate."""
    try:
        if b"-----BEGIN" in data:
            return x509.load_pem_x509_certificates(data)
        return [x509.load_der_x509_certificate(data)]
    except ValueError as e:
        raise CertError(Message("cert_invalid")) from e


def info(path: str) -> dict | None:
    """Details of the first certificate of a file, or None if absent or unreadable."""
    if not path or not os.path.isfile(path):
        return None
    try:
        certs = load_certs(Path(path).read_bytes())
    except (OSError, CertError):
        return None
    return {**describe(certs[0]), "path": path, "chain_length": len(certs)}


def _load_key(data: bytes, password: str | None):
    pw = password.encode() if password else None
    try:
        if b"-----BEGIN" in data:
            return serialization.load_pem_private_key(data, password=pw)
        return serialization.load_der_private_key(data, password=pw)
    except (ValueError, TypeError) as e:
        raise CertError(Message("key_invalid")) from e


def _write(path: Path, data: bytes, private: bool = False) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:40] or "file"


def decode_upload(data_b64: str) -> bytes:
    try:
        return base64.b64decode(data_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise CertError(Message("cert_invalid")) from e


def store_upload(directory: Path, kind: str, filename: str, data: bytes, password: str = "") -> tuple[str, dict]:
    """Validate and store an uploaded file. ``kind``: ca | client_cert | client_key.

    Certificates are normalised to PEM. A key is checked (with its password) and stored as uploaded.
    Returns (path, details).
    """
    stem = f"{kind}-{_stamp()}-{_safe(Path(filename).stem)}"
    if kind in ("ca", "client_cert"):
        certs = load_certs(data)
        pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
        path = directory / f"{stem}.pem"
        _write(path, pem)
        return str(path), {**describe(certs[0]), "chain_length": len(certs)}
    if kind == "client_key":
        _load_key(data, password)
        path = directory / f"{stem}.key"
        _write(path, data, private=True)
        return str(path), {}
    raise ValueError(kind)


def check_pair(cert_path: str, key_path: str, password: str = "") -> None:
    """Raise CertError if the private key does not belong to the certificate."""
    cert = load_certs(Path(cert_path).read_bytes())[0]
    key = _load_key(Path(key_path).read_bytes(), password)
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    enc = serialization.Encoding.DER
    if cert.public_key().public_bytes(enc, pub) != key.public_key().public_bytes(enc, pub):
        raise CertError(Message("key_mismatch"))


def generate_self_signed(directory: Path, cn: str, days: int) -> tuple[str, str, str, dict]:
    """New RSA 2048 key and self-signed client certificate for pxGrid.

    Returns (certificate path, key path, certificate PEM, details). New file names every time:
    the running client keeps its files until the new paths are saved in the configuration.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    stem = f"pxgrid-client-{_stamp()}"
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path = directory / f"{stem}.pem"
    key_path = directory / f"{stem}.key"
    _write(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()), private=True)
    _write(cert_path, cert_pem)
    return str(cert_path), str(key_path), cert_pem.decode(), describe(cert)
