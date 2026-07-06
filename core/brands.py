"""Known brand names/domains commonly impersonated in phishing campaigns.

Used for lookalike-domain and lookalike-sender-ID detection across the
email, SMS, and URL/QR analyzers.
"""

from __future__ import annotations

# Map of brand name -> set of legitimate root domains for that brand.
KNOWN_BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com"},
    "google": {"google.com", "gmail.com"},
    "netflix": {"netflix.com"},
    "bankofamerica": {"bankofamerica.com"},
    "wellsfargo": {"wellsfargo.com"},
    "chase": {"chase.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "irs": {"irs.gov"},
    "usps": {"usps.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "dhl": {"dhl.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
}

# Short alphanumeric sender IDs carriers allow brands to register (used for
# SMS sender-ID impersonation checks). Lowercase, no spaces.
KNOWN_SMS_SENDER_IDS: set[str] = {
    "paypal",
    "amazon",
    "apple",
    "microsoft",
    "google",
    "netflix",
    "bankofamerica",
    "wellsfargo",
    "chase",
    "facebook",
    "instagram",
    "irs",
    "usps",
    "fedex",
    "ups",
    "dhl",
    "coinbase",
    "binance",
    "venmo",
}

# Domains of well-known URL shortening services. Not inherently malicious,
# but they hide the true destination and are heavily used in phishing.
URL_SHORTENERS: set[str] = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorte.st",
    "tiny.cc",
    "rb.gy",
    "shorturl.at",
    "v.gd",
}

# TLDs disproportionately abused for cheap, throwaway phishing domains.
SUSPICIOUS_TLDS: set[str] = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "work",
    "click",
    "link",
    "loan",
    "men",
    "review",
    "country",
    "kim",
    "science",
}
