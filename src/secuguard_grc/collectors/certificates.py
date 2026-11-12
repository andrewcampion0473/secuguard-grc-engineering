"""TLS certificates held in AWS Certificate Manager, read from the certificates themselves."""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .base import Collector, optional

ALL_KEY_TYPES = ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
                 "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]


def parse_certificate(pem: str) -> dict:
    """Facts taken from the certificate itself, so they do not depend on what a service reports."""
    cert = x509.load_pem_x509_certificate(pem.encode())
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", key.curve.key_size
    else:
        key_type, key_bits = type(key).__name__, None
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_signed": cert.subject == cert.issuer,
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "key_type": key_type,
        "key_bits": key_bits,
        "signature_hash": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
        "serial_number": format(cert.serial_number, "x"),
    }


def _list(acm):
    try:
        pages = acm.get_paginator("list_certificates").paginate(Includes={"keyTypes": ALL_KEY_TYPES})
        return [c for page in pages for c in page.get("CertificateSummaryList", [])]
    except Exception:  # an older or simulated API that does not accept the key type filter
        pages = acm.get_paginator("list_certificates").paginate()
        return [c for page in pages for c in page.get("CertificateSummaryList", [])]


def collect(session):
    acm = session.client("acm")
    certificates = []
    for summary in _list(acm):
        arn = summary["CertificateArn"]
        described = optional(lambda: acm.describe_certificate(CertificateArn=arn), set(), "Certificate") or {}
        body = optional(lambda: acm.get_certificate(CertificateArn=arn), {"RequestInProgressException"})
        pem = (body or {}).get("Certificate")
        certificates.append({
            "arn": arn,
            "domain_name": summary.get("DomainName"),
            "type": described.get("Type"),
            "status": described.get("Status"),
            "in_use_by": described.get("InUseBy", []),
            "parsed": parse_certificate(pem) if pem else None,
        })
    return {"certificates": certificates}


COLLECTOR = Collector(
    name="certificates",
    description=(
        "Every certificate in AWS Certificate Manager: who issued it, when it expires, its key "
        "type and size, how it was signed, and what is using it. The key and date facts are read "
        "from the certificate itself."
    ),
    api_calls=["acm:ListCertificates", "acm:DescribeCertificate", "acm:GetCertificate"],
    relevant_to={
        "pci_dss_4_0_1": ["4.2"],
        "soc_2": ["CC6.7"],
        "fedramp_20x": ["KSI-SVC-ASM", "KSI-SVC-SIN", "KSI-SVC-VCM"],
    },
    collect=collect,
)
