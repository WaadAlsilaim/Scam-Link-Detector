# Linecheck — Scam Link Detector

A URL scam/phishing classifier: lexical/structural feature extraction, an XGBoost model, a curated allowlist for well-known legitimate domains, and an optional live-enrichment layer, served through a FastAPI backend with a web scanner UI.

## Interface

![Linecheck scanner interface](docs/screenshot.png)

Paste a URL, hit Scan (or click one of the example chips), and it returns a verdict, a risk score, and the specific signals that drove the decision.

## Structure
- `src/generate_dataset.py` — builds the labeled training dataset from a real-world URL dataset (~550K URLs, phishing + legitimate)
- `src/features.py` — ~28 lexical/structural URL features, no network calls
- `src/train.py` — trains Random Forest + XGBoost, picks the best by ROC-AUC, saves to `models/`
- `src/allowlist.py` — curated list of well-known legitimate domains that short-circuits to `likely_safe`, matched on the exact registered domain so lookalikes can't bypass it
- `src/enrichment.py` — optional live checks: SSL cert, WHOIS domain age, Google Safe Browsing (stubbed for environments with no outbound internet)
- `src/predict.py` — combines the lexical model score, allowlist, and enrichment into a final verdict
- `app.py` — FastAPI app exposing `POST /check` and serving the web UI at `/`
- `static/index.html` — the scanner front end

## Run locally
```bash
pip install -r requirements.txt
python3 src/generate_dataset.py   # regenerate data if needed
python3 src/train.py              # retrain if needed
python3 app.py                    # serves UI + API on http://0.0.0.0:8000
```

Open `http://localhost:8000/` for the web front end.

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
  "lexical_score": 0.9996,
  "verdict": "likely_scam",
  "top_signals": ["uses a TLD commonly abused for scam sites", "..."],
  "enrichment": null,
  "allowlisted": null
}
```

`verdict` thresholds: `>=0.75` likely_scam, `>=0.4` suspicious, else likely_safe.

## Model

Trained on a real-world dataset of ~550K URLs (~156K real phishing/malicious URLs, ~393K real legitimate URLs), sourced from a public GitHub-hosted dataset derived from PhishTank and web crawls. ~58K rows are sampled for training, split 80/20 with stratification.

Random Forest and XGBoost are both trained; XGBoost wins on held-out data:

**89.8% accuracy, 90.9% precision, 87.6% recall, 0.964 ROC-AUC**

These numbers reflect real-world generalization, not memorized patterns — an earlier synthetic-data version of this model scored a suspicious ~100%, which turned out to mean it had only learned its own data generator's rules rather than real phishing patterns. Switching to real data was what actually made it useful.

## Known limitations
- A lexical-only model will occasionally miss brand-new or unusual scam sites, and occasionally flag unusual-but-legitimate domains. The allowlist mitigates this for well-known sites; `use_enrichment: true` (live SSL/domain-age checks) helps close the rest of the gap.
- Enrichment's WHOIS and Safe Browsing checks are stubbed pending real API keys and outbound network access in production.

## Next steps toward deployment
- Wire up `enrichment.py`'s WHOIS/Safe Browsing stubs to real APIs — the biggest lever left for catching brand-new scam domains a lexical model alone would miss
- Add rate limiting / auth to `app.py` before exposing publicly
- Package as a browser extension that calls `POST /check` on link hover/click
- Periodically retrain on fresh data — phishing patterns drift over time

## Credits
Training data derived from [cyberholics/Malicious-URL-detector](https://github.com/cyberholics/Malicious-URL-detector).
