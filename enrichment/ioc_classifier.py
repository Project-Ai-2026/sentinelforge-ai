import re

def classify_ioc(ioc: str) -> str:
    ioc = ioc.strip()

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"

    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "md5"

    if re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "sha1"

    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "sha256"

    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"

    if "." in ioc:
        return "domain"

    return "unknown"
