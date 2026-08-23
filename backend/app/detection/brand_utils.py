"""Shared brand impersonation helpers (rules + explainability)."""

from __future__ import annotations

import re

# Commonly impersonated brands → official domains
BRANDS: dict[str, list[str]] = {
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com", "office365.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.sg", "amazon.com.my"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "netflix": ["netflix.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "maybank": ["maybank.com", "maybank2u.com.my", "maybank2u.com"],
    "cimb": ["cimb.com", "cimbclicks.com.my", "cimbbank.com.my"],
    "bank islam": ["bankislam.biz", "bankislam.com.my"],
    "utm": ["utm.my"],
    "hsbc": ["hsbc.com", "hsbc.com.my"],
    "grab": ["grab.com", "grab.my"],
    "shopee": ["shopee.com", "shopee.com.my"],
}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def registered_domain(hostname: str) -> str:
    """Best-effort eTLD+1 for common cases (not a full PSL)."""
    host = (hostname or "").lower().removeprefix("www.")
    if not host:
        return ""
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    # country-second-level: example.com.my / co.uk
    if parts[-1] in {"my", "uk", "au", "sg", "br", "jp", "kr", "za"} and len(parts) >= 3:
        if parts[-2] in {"com", "co", "net", "org", "gov", "edu", "ac"}:
            return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def brand_in_hostname(hostname: str) -> dict | None:
    """
    Detect brand tokens used in subdomains while the registered domain is unrelated.

    Example: paypal.com.security-check.example.com → brand paypal, registered example.com
    """
    host = (hostname or "").lower().removeprefix("www.")
    if not host:
        return None
    reg = registered_domain(host)
    labels = host.replace("-", ".").split(".")
    for brand, domains in BRANDS.items():
        token = brand.split()[0]
        if token not in labels and token not in host:
            continue
        if any(reg == d or reg.endswith("." + d) or host.endswith(d) for d in domains):
            continue
        # Brand appears but registered domain is not the official brand domain
        if token in host and not any(host.endswith(d) for d in domains):
            return {
                "brand": brand,
                "hostname": host,
                "registered_domain": reg,
                "official_domains": domains,
            }
    return None


def lookalike_brand_domain(hostname: str) -> dict | None:
    """Detect domains that are edit-distance close to a known brand domain."""
    host = (hostname or "").lower().removeprefix("www.")
    reg = registered_domain(host)
    if not reg:
        return None
    reg_norm = normalize_homoglyph(reg)
    for brand, domains in BRANDS.items():
        for legit in domains:
            if reg == legit or reg_norm == normalize_homoglyph(legit):
                if reg == legit:
                    continue
                # Homoglyph / digit-substitution of an official domain
                return {
                    "brand": brand,
                    "hostname": host,
                    "registered_domain": reg,
                    "official_domain": legit,
                    "distance": levenshtein(reg, legit),
                }
            dist = levenshtein(reg, legit)
            # Close lookalikes only (paypa1.com vs paypal.com)
            if 0 < dist <= 2 and abs(len(reg) - len(legit)) <= 2:
                return {
                    "brand": brand,
                    "hostname": host,
                    "registered_domain": reg,
                    "official_domain": legit,
                    "distance": dist,
                }
            # Brand token with extra words: paypal-login.com / paypa1-login.com
            base = legit.split(".")[0]
            base_norm = normalize_homoglyph(base)
            host_labels = reg.replace("-", ".").split(".")
            for lbl in host_labels:
                lbl_norm = normalize_homoglyph(lbl)
                dist_lbl = levenshtein(lbl_norm, base_norm)
                # Exact brand token, homoglyph (paypa1→paypal), or 1-edit lookalike
                if lbl == base or (lbl_norm == base_norm and lbl != base) or (
                    0 < dist_lbl <= 1 and abs(len(lbl) - len(base)) <= 1
                ):
                    if reg != legit and not any(reg.endswith(d) for d in domains):
                        return {
                            "brand": brand,
                            "hostname": host,
                            "registered_domain": reg,
                            "official_domain": legit,
                            "distance": dist if dist <= 5 else None,
                        }
    return None


_DIGIT_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


def normalize_homoglyph(text: str) -> str:
    return re.sub(r"[^a-z0-9.]", "", (text or "").lower().translate(_DIGIT_MAP))
