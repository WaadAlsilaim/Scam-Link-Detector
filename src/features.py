"""Lexical + structural feature extraction for URL scam/phishing detection.
No network calls at extraction time -- everything derives from the URL string itself.
"""
import re
import math
from urllib.parse import urlparse
import tldextract

BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix", "bankofamerica",
    "wellsfargo", "chase", "instagram", "facebook", "linkedin", "dhl", "fedex",
    "usps", "irs", "coinbase", "binance", "steam", "ebay", "twitter", "whatsapp",
    "outlook", "office365", "icloud", "yahoo", "aol", "americanexpress", "hsbc",
    "barclays", "natwest", "santander", "citibank", "usbank", "capitalone",
    "tiktok", "snapchat", "spotify", "dropbox", "adobe", "docusign", "zoom",
    "ups", "target", "walmart", "costco", "bestbuy", "verizon", "att", "tmobile",
    "comcast", "xfinity", "linkedin", "discord", "twitch", "roblox", "epicgames",
    "playstation", "xbox", "nintendo", "airbnb", "booking", "expedia", "uber",
    "lyft", "doordash", "grubhub", "instacart", "chime", "venmo", "zelle",
    "westernunion", "moneygram", "revolut", "wise", "robinhood", "fidelity",
    "schwab", "vanguard", "etrade", "irs", "socialsecurity", "medicare",
]

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
                   "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly"}

SUSPICIOUS_TLDS = {"tk", "xyz", "top", "gq", "ml", "cf", "buzz", "click", "info",
                    "work", "live", "support", "loan", "win", "bid", "review",
                    "party", "trade", "date", "faith", "download", "stream", "gdn"}
KEYWORDS = ["verify", "login", "secure", "account", "update", "confirm", "signin",
            "billing", "suspended", "unlock", "reward", "gift", "prize"]

_extract = tldextract.TLDExtract(suffix_list_urls=())  # offline mode, no live fetch


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur = [i + 1]
        for j, cb in enumerate(b):
            cur.append(min(prev[j + 1] + 1, cur[j] + 1, prev[j] + (ca != cb)))
        prev = cur
    return prev[-1]


def closest_brand_distance(domain: str):
    tokens = [domain] + re.split(r"[-_0-9]+", domain)
    tokens = [t for t in tokens if t]
    best_brand, best_dist = None, 99
    for b in BRANDS:
        for t in tokens:
            d = levenshtein(t, b)
            if d < best_dist:
                best_brand, best_dist = b, d
    return best_brand, best_dist


def extract_features(url: str) -> dict:
    url = url.strip()
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except ValueError:
        # malformed URL (e.g. stray brackets breaking IPv6 parsing) -- fall back
        # to a blank parse result rather than crashing the whole pipeline
        parsed = urlparse("http://invalid-url-placeholder.invalid")
    try:
        ext = _extract(url)
    except Exception:
        ext = _extract("invalid-url-placeholder.invalid")
    host = parsed.netloc.split("@")[-1].split(":")[0]
    domain = ext.domain or ""
    suffix = ext.suffix or ""
    subdomain = ext.subdomain or ""
    path = parsed.path or ""
    query = parsed.query or ""

    is_ip = bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host))
    brand, brand_dist = closest_brand_distance(domain)
    exact_brand_match = domain in BRANDS
    registered_domain = f"{domain}.{suffix}" if suffix else domain

    feats = {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "domain_hyphens": domain.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_at_symbols": url.count("@"),
        "num_equals": url.count("="),
        "num_percent": url.count("%"),
        "num_subdomains": len([s for s in subdomain.split(".") if s]) if subdomain else 0,
        "is_ip_host": int(is_ip),
        "is_https": int(parsed.scheme == "https"),
        "suspicious_tld": int(suffix.split(".")[-1] in SUSPICIOUS_TLDS) if suffix else 0,
        "tld_length": len(suffix.split(".")[-1]) if suffix else 0,
        "is_shortener": int(registered_domain.lower() in URL_SHORTENERS),
        "keyword_count": sum(1 for k in KEYWORDS if k in url.lower()),
        "domain_entropy": shannon_entropy(domain),
        "host_entropy": shannon_entropy(host),
        "brand_lev_distance": brand_dist,
        "exact_brand_match": int(exact_brand_match),
        "brand_in_subdomain_not_domain": int(
            any(b in subdomain.lower() for b in BRANDS) and not exact_brand_match
        ),
        "brand_in_path": int(any(b in path.lower() for b in BRANDS)),
        "has_port": int(parsed.port is not None) if hasattr(parsed, "port") else 0,
        "digit_ratio": (sum(c.isdigit() for c in host) / len(host)) if host else 0,
        "path_depth": len([p for p in path.split("/") if p]),
        "num_query_params": len(query.split("&")) if query else 0,
    }
    return feats


FEATURE_NAMES = list(extract_features("http://example.com/test").keys())


if __name__ == "__main__":
    import json
    for test_url in ["http://paypa1-secure-login.tk/verify/account?id=39dka",
                      "https://www.amazon.com/products/electronics?ref=nav"]:
        print(test_url)
        print(json.dumps(extract_features(test_url), indent=2))
