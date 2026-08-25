import json
from pathlib import Path
from urllib.parse import urlparse
import joblib
import pandas as pd
import tldextract

from features import extract_features
from enrichment import enrich
from allowlist import is_allowlisted

_MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
_model = joblib.load(_MODELS_DIR / "model.joblib")
with open(_MODELS_DIR / "feature_names.json") as f:
    _feature_names = json.load(f)
_extract = tldextract.TLDExtract(suffix_list_urls=())


def _verdict_from_score(score: float) -> str:
    if score >= 0.75:
        return "likely_scam"
    if score >= 0.4:
        return "suspicious"
    return "likely_safe"


def predict(url: str, use_enrichment: bool = False, safe_browsing_api_key: str = None) -> dict:
    feats = extract_features(url)

    ext = _extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    if is_allowlisted(registered_domain):
        result = {
            "url": url,
            "lexical_score": 0.0,
            "verdict": "likely_safe",
            "top_signals": [],
            "allowlisted": True,
        }
        if use_enrichment:
            host = urlparse(url if "://" in url else "http://" + url).netloc.split("@")[-1].split(":")[0]
            result["enrichment"] = enrich(url, host, safe_browsing_api_key)
        return result

    X = pd.DataFrame([feats])[_feature_names]
    score = float(_model.predict_proba(X)[0][1])

    result = {
        "url": url,
        "lexical_score": round(score, 4),
        "verdict": _verdict_from_score(score),
        "top_signals": _top_signals(feats),
    }

    if use_enrichment:
        host = urlparse(url if "://" in url else "http://" + url).netloc.split("@")[-1].split(":")[0]
        enrichment = enrich(url, host, safe_browsing_api_key)
        result["enrichment"] = enrichment

        # Nudge the verdict if a live signal strongly disagrees with the lexical score
        if enrichment.get("flagged_by_safe_browsing") is True:
            result["verdict"] = "likely_scam"
            result["lexical_score"] = max(result["lexical_score"], 0.95)
        elif enrichment.get("domain_age_days") is not None and enrichment["domain_age_days"] < 30 and score > 0.3:
            result["verdict"] = "likely_scam" if score >= 0.4 else "suspicious"

    return result


def _top_signals(feats: dict, top_n: int = 4) -> list:
    """Human-readable flags for the response -- not SHAP values, just the clearest
    rule-based tells so the API response is explainable without extra compute."""
    signals = []
    if feats["is_ip_host"]:
        signals.append("uses a raw IP address instead of a domain name")
    if feats["suspicious_tld"]:
        signals.append("uses a TLD commonly abused for scam sites")
    if feats["exact_brand_match"] == 0 and feats["brand_lev_distance"] <= 2:
        signals.append("domain closely resembles a known brand (possible typosquat)")
    if feats["brand_in_subdomain_not_domain"]:
        signals.append("brand name appears only in the subdomain, not the real domain")
    if feats["num_at_symbols"] > 0:
        signals.append("contains an '@' symbol, which can hide the real destination")
    if not feats["is_https"]:
        signals.append("not served over HTTPS")
    if feats["keyword_count"] >= 2:
        signals.append("multiple urgency/verification keywords in the URL")
    if feats["domain_entropy"] > 3.8:
        signals.append("domain name looks randomly generated")
    return signals[:top_n]


if __name__ == "__main__":
    tests = [
        "http://paypa1-secure-login.tk/verify/account?id=39dka",
        "https://www.amazon.com/products/electronics?ref=nav",
        "http://192.168.14.22/wp-admin/update.php",
    ]
    for t in tests:
        print(json.dumps(predict(t), indent=2))
