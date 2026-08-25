# Scam Link Detector

A URL scam/phishing classifier: lexical/structural feature extraction -> XGBoost model -> FastAPI serving layer with an optional live-enrichment hook.

## Structure
- `src/generate_dataset.py` — builds the labeled training dataset (synthetic in this sandbox; swap for real PhishTank/OpenPhish + Tranco CSVs in production)
- `src/features.py` — 26 lexical/structural URL features, no network calls
- `src/train.py` — trains Random Forest + XGBoost, picks the best by ROC-AUC, saves to `models/`
- `src/enrichment.py` — optional live checks: SSL cert, WHOIS domain age, Google Safe Browsing (stubbed where the sandbox has no outbound internet)
- `src/predict.py` — combines the lexical model score with enrichment into a final verdict
- `app.py` — FastAPI app exposing `POST /check`

## Run locally
```bash
pip install -r requirements.txt
python3 src/generate_dataset.py   # regenerate data if needed
python3 src/train.py              # retrain if needed
python3 app.py                    # serves on http://0.0.0.0:8000
```

## API

`POST /check`
```json
{
  "url": "http://paypa1-secure-login.tk/verify/account",
  "use_enrichment": false
}
```

Response:
```json
{
  "url": "...",
  "lexical_score": 0.9999,
  "verdict": "likely_scam",
  "top_signals": ["uses a TLD commonly abused for scam sites", "..."],
  "enrichment": null
}
```

`verdict` thresholds: `>=0.75` likely_scam, `>=0.4` suspicious, else likely_safe.

## Known limitation (important)
Training data has switched to a **real dataset of ~550K URLs** (150K real phishing/malicious URLs + 390K real legitimate URLs, from a public GitHub-hosted dataset derived from PhishTank + web crawls). ~58K rows are sampled for training. This generalizes far better than the earlier synthetic version — it now correctly flags unseen scam patterns (typosquats, URL shorteners, suspicious TLDs, raw IPs) it was never trained on directly.

Current real-data performance (XGBoost, held-out test set): **89.8% accuracy, 90.9% precision, 87.6% recall, 0.964 ROC-AUC**. These are honest numbers, not the artificially perfect ones from the earlier synthetic-data version. Expect occasional misses on very new or unusual scam sites, and occasional false positives on unusual-but-legit domains — this is inherent to any lexical-only model that doesn't visit the page or check reputation databases. Combining with the enrichment checks (`use_enrichment: true`) closes some of that gap.

## Next steps toward deployment
- Wire up `enrichment.py`'s WHOIS/Safe Browsing stubs to real APIs (needs API keys + outbound network) — this is the biggest lever left for catching brand-new scam domains a lexical model alone would miss
- Add rate limiting / auth to `app.py` before exposing publicly
- Package as a browser extension that calls `POST /check` on link hover/click
- Periodically retrain on fresh data — phishing patterns drift over time
