"""
Builds the labeled URL dataset for the scam/phishing detector using a REAL public
dataset (549K real URLs, sourced from PhishTank-derived phishing/bad URLs mixed
with real crawled legitimate URLs) rather than synthetic/rule-based URLs.

Source: https://github.com/cyberholics/Malicious-URL-detector (phishing_site_urls.csv)
Falls back to the old synthetic generator (see generate_synthetic_dataset below)
only if the real dataset file isn't available, so this script still runs standalone.
"""
import random
import string
from pathlib import Path
import pandas as pd

random.seed(42)

REAL_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "muld" / "phishing_site_urls.csv"
OUT_PATH = Path(__file__).resolve().parent.parent / "data" / "urls_labeled.csv"
N_PER_CLASS = 30000


def build_from_real_data(n_per_class=N_PER_CLASS):
    df = pd.read_csv(REAL_DATA_PATH)
    df = df.dropna(subset=["URL", "Label"])
    df["Label"] = df["Label"].str.strip().str.lower()
    bad = df[df["Label"] == "bad"]["URL"]
    good = df[df["Label"] == "good"]["URL"]

    n_bad = min(n_per_class, len(bad))
    n_good = min(n_per_class, len(good))

    bad_sample = bad.sample(n_bad, random_state=42)
    good_sample = good.sample(n_good, random_state=42)

    rows = [{"url": u, "label": 1} for u in bad_sample] + [{"url": u, "label": 0} for u in good_sample]
    out = pd.DataFrame(rows).drop_duplicates(subset="url").sample(frac=1, random_state=42).reset_index(drop=True)
    return out


# ---- Fallback: synthetic generator (kept for offline/no-real-data situations) ----

BRANDS = ["paypal", "amazon", "apple", "microsoft", "google", "netflix", "bankofamerica",
          "wellsfargo", "chase", "instagram", "facebook", "linkedin", "dhl", "fedex",
          "usps", "irs", "coinbase", "binance", "steam", "ebay"]

LEGIT_DOMAINS = [
    "paypal.com", "amazon.com", "apple.com", "microsoft.com", "google.com",
    "netflix.com", "bankofamerica.com", "wellsfargo.com", "chase.com",
    "instagram.com", "facebook.com", "linkedin.com", "dhl.com", "fedex.com",
    "usps.com", "irs.gov", "coinbase.com", "binance.com", "steampowered.com",
    "ebay.com", "wikipedia.org", "github.com", "stackoverflow.com", "bbc.com",
    "nytimes.com", "reddit.com", "spotify.com", "dropbox.com", "adobe.com",
    "salesforce.com", "zoom.us", "slack.com", "notion.so", "figma.com",
]

SUSPICIOUS_TLDS = ["tk", "xyz", "top", "gq", "ml", "cf", "buzz", "click", "info", "work"]
KEYWORDS = ["verify", "login", "secure", "account", "update", "confirm", "signin",
            "billing", "suspended", "unlock", "reward", "gift", "prize"]


def rand_str(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def homoglyph_swap(brand):
    swaps = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
    chars = list(brand)
    idx = random.randrange(len(chars))
    c = chars[idx]
    if c in swaps and random.random() < 0.6:
        chars[idx] = swaps[c]
    else:
        chars.insert(random.randrange(len(chars) + 1), random.choice(string.ascii_lowercase))
    return "".join(chars)


def make_phishing_url():
    brand = random.choice(BRANDS)
    pattern = random.choice(["typosquat", "subdomain_stuff", "ip_host", "raw_random", "keyword_stuff"])

    if pattern == "typosquat":
        fake = homoglyph_swap(brand)
        tld = random.choice(SUSPICIOUS_TLDS + ["com", "net"])
        host = f"{fake}.{tld}"
    elif pattern == "subdomain_stuff":
        subs = [brand, random.choice(KEYWORDS), rand_str(5)]
        random.shuffle(subs)
        tld = random.choice(SUSPICIOUS_TLDS)
        host = ".".join(subs) + f".{rand_str(6)}.{tld}"
    elif pattern == "ip_host":
        host = ".".join(str(random.randint(1, 255)) for _ in range(4))
    elif pattern == "keyword_stuff":
        tld = random.choice(SUSPICIOUS_TLDS)
        host = f"{brand}-{random.choice(KEYWORDS)}-{random.choice(KEYWORDS)}.{tld}"
    else:  # raw_random
        tld = random.choice(SUSPICIOUS_TLDS)
        host = f"{rand_str(random.randint(8, 16))}.{tld}"

    path_depth = random.randint(0, 4)
    path = "/".join(rand_str(random.randint(3, 10)) for _ in range(path_depth))
    query = ""
    if random.random() < 0.5:
        params = "&".join(f"{rand_str(3)}={rand_str(random.randint(4, 20))}" for _ in range(random.randint(1, 3)))
        query = f"?{params}"
    at_symbol = "@" + rand_str(5) if random.random() < 0.08 else ""
    scheme = "http" if random.random() < 0.6 else "https"
    www_prefix = "www." if random.random() < 0.1 else ""
    return f"{scheme}://{www_prefix}{host}{at_symbol}/{path}{query}"


def make_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path_depth = random.randint(0, 3)
    path_words = ["home", "products", "about", "support", "help", "docs", "blog",
                  "account", "settings", "search", "profile", "en-us", "shop"]
    path = "/".join(random.choice(path_words) for _ in range(path_depth))
    query = ""
    if random.random() < 0.3:
        params = "&".join(f"{k}={rand_str(random.randint(3, 8))}" for k in random.sample(
            ["id", "ref", "page", "q", "lang"], k=random.randint(1, 2)))
        query = f"?{params}"
    prefix = "www." if random.random() < 0.6 else ""
    return f"https://{prefix}{domain}/{path}{query}"


def build_synthetic(n_per_class=10000):
    rows = []
    for _ in range(n_per_class):
        rows.append({"url": make_phishing_url(), "label": 1})
    for _ in range(n_per_class):
        rows.append({"url": make_legit_url(), "label": 0})
    df = pd.DataFrame(rows).drop_duplicates(subset="url").sample(frac=1, random_state=42).reset_index(drop=True)
    return df


if __name__ == "__main__":
    if REAL_DATA_PATH.exists():
        print(f"Building dataset from real data: {REAL_DATA_PATH}")
        df = build_from_real_data()
    else:
        print("Real dataset not found, falling back to synthetic generator.")
        df = build_synthetic(10000)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_PATH, index=False)
    print(f"Wrote {len(df)} rows -> {OUT_PATH}")
    print(df["label"].value_counts())

