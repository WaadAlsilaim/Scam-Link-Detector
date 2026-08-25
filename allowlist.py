"""
Curated allowlist of well-known, unmistakably legitimate domains.

Why this exists: a lexical-only ML model has no notion of "this is a globally
famous, 20-year-old site" -- it only sees URL structure. Sites like Wikipedia
that aren't consumer brands (so they're not in the typosquat brand list) and
whose URL shape happens to overlap with noisy training examples can get
inconsistent, occasionally-wrong scores from the model alone. Real deployed
phishing filters handle this the same way: trust an allowlist of unmistakably
legitimate domains outright rather than re-scoring them lexically every time.

Matching is on the REGISTERED domain (domain + public suffix) computed by
tldextract, not substring matching -- so "wikipedia.org.phish-site.tk" does
NOT match "wikipedia.org" (its registered domain is "phish-site.tk").
"""

ALLOWLISTED_DOMAINS = {
    # search / reference
    "google.com", "wikipedia.org", "bing.com", "duckduckgo.com",
    # tech / dev
    "github.com", "gitlab.com", "stackoverflow.com", "microsoft.com",
    "apple.com", "mozilla.org", "python.org", "npmjs.com",
    # commerce
    "amazon.com", "ebay.com", "walmart.com", "target.com", "costco.com",
    "bestbuy.com", "etsy.com",
    # finance
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "coinbase.com", "binance.com", "americanexpress.com",
    # social / comms
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "whatsapp.com", "reddit.com", "discord.com", "slack.com", "zoom.us",
    # media / news
    "youtube.com", "netflix.com", "spotify.com", "nytimes.com", "bbc.com",
    "cnn.com",
    # productivity / cloud
    "dropbox.com", "adobe.com", "salesforce.com", "notion.so", "figma.com",
    "office.com", "icloud.com",
    # shipping / gov
    "ups.com", "fedex.com", "dhl.com", "usps.com", "irs.gov",
    # travel
    "airbnb.com", "booking.com", "expedia.com", "uber.com", "lyft.com",
}


def is_allowlisted(registered_domain: str) -> bool:
    return registered_domain.lower() in ALLOWLISTED_DOMAINS
