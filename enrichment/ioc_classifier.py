import re

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_URL_RE    = re.compile(r"^https?://", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def classify_ioc(ioc: str) -> str:
    ioc = ioc.strip()

    if _IP_RE.match(ioc):
        return "ip"

    if _MD5_RE.match(ioc):
        return "md5"

    if _SHA1_RE.match(ioc):
        return "sha1"

    if _SHA256_RE.match(ioc):
        return "sha256"

    if _URL_RE.match(ioc):
        return "url"

    if _DOMAIN_RE.match(ioc):
        return "domain"

    return "unknown"
