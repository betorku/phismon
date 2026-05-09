import os
import json
import math
import re
import time
import datetime
import requests
import tldextract

from urllib.parse import urlparse
from rapidfuzz import fuzz
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================================================
# OPTIONAL WHOIS SUPPORT
# =========================================================

try:
    import whois
    WHOIS_ENABLED = True
except Exception:
    WHOIS_ENABLED = False

# =========================================================
# CONFIGURATION
# =========================================================

TAVILY_API_KEY = os.getenv("TAVILY_API_KEY")

OUTPUT_FILE = "data.json"

BRAND = "bni"

OFFICIAL_DOMAINS = [
    "bni.co.id"
]

EXCLUDED_DOMAINS = [
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "youtube.com",
    "twitter.com",
    "x.com",
    "tiktok.com",
]

SEARCH_QUERIES = [
    "bni direct login",
    "bni cash management",
    "bn1 login",
    "bni secure portal",
    "bni verification",
    "bni account update",
    "bni-direct login",
    "bnidirect secure",
    "bni internet banking login",
]

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "update",
    "portal",
    "auth",
    "cash",
    "token",
    "account",
    "password",
    "banking",
    "otp",
    "wallet",
]

SUSPICIOUS_TLDS = [
    "xyz",
    "top",
    "site",
    "online",
    "buzz",
    "click",
    "shop",
    "live",
    "icu",
    "info",
]

PHISHING_PATTERNS = [
    "bn1",
    "bnii",
    "bnii",
    "b-n-i",
    "bnid",
    "bnicash",
    "bnidirect",
    "bnisecure",
]

# =========================================================
# HTTP SESSION WITH RETRIES
# =========================================================

session = requests.Session()

retries = Retry(
    total=3,
    backoff_factor=2,
    status_forcelist=[429, 500, 502, 503, 504],
)

session.mount(
    "https://",
    HTTPAdapter(max_retries=retries)
)

# =========================================================
# HELPERS
# =========================================================

def normalize_domain(url):

    ext = tldextract.extract(url)

    return f"{ext.domain}.{ext.suffix}".lower()


def calculate_entropy(text):

    if not text:
        return 0

    probabilities = [
        float(text.count(c)) / len(text)
        for c in set(text)
    ]

    return -sum(
        p * math.log(p, 2)
        for p in probabilities
    )


def is_official_domain(domain):

    return any(
        domain.endswith(d)
        for d in OFFICIAL_DOMAINS
    )


def get_domain_age(domain):

    if not WHOIS_ENABLED:
        return 9999

    try:

        result = whois.whois(domain)

        creation_date = result.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:

            age = (
                datetime.datetime.utcnow() - creation_date
            ).days

            return age

    except Exception:
        pass

    return 9999


def brand_similarity(domain):

    root = tldextract.extract(domain).domain

    score = fuzz.ratio(root, BRAND)

    for pattern in PHISHING_PATTERNS:

        if pattern in root:
            score += 25

    return min(score, 100)


def contains_suspicious_keywords(url):

    url = url.lower()

    return [
        k for k in SUSPICIOUS_KEYWORDS
        if k in url
    ]


def has_suspicious_tld(domain):

    suffix = tldextract.extract(domain).suffix

    return suffix in SUSPICIOUS_TLDS


def contains_random_strings(domain):

    return bool(
        re.search(r"[a-z0-9]{8,}", domain)
    )


# =========================================================
# THREAT SCORING
# =========================================================

def calculate_risk(url):

    parsed = urlparse(url)

    domain = normalize_domain(url)

    score = 0

    reasons = []

    # -----------------------------------------------------
    # OFFICIAL DOMAIN CHECK
    # -----------------------------------------------------

    if is_official_domain(domain):

        return {
            "score": 0,
            "status": "Official",
            "reasons": ["Official domain"],
            "domain_age_days": 9999,
            "entropy": 0,
            "brand_similarity": 100,
        }

    # -----------------------------------------------------
    # BRAND SIMILARITY
    # -----------------------------------------------------

    similarity = brand_similarity(domain)

    if similarity >= 90:
        score += 45
        reasons.append(
            f"Very high brand similarity ({similarity})"
        )

    elif similarity >= 70:
        score += 30
        reasons.append(
            f"High brand similarity ({similarity})"
        )

    elif similarity >= 50:
        score += 15
        reasons.append(
            f"Medium brand similarity ({similarity})"
        )

    # -----------------------------------------------------
    # DASH ABUSE
    # -----------------------------------------------------

    if "-" in domain:
        score += 10
        reasons.append("Contains dash")

    # -----------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------------------------

    matched_keywords = contains_suspicious_keywords(url)

    if matched_keywords:

        keyword_score = min(
            len(matched_keywords) * 10,
            30
        )

        score += keyword_score

        reasons.append(
            f"Suspicious keywords: "
            f"{', '.join(matched_keywords)}"
        )

    # -----------------------------------------------------
    # SUSPICIOUS TLD
    # -----------------------------------------------------

    if has_suspicious_tld(domain):

        score += 20

        reasons.append("Suspicious TLD")

    # -----------------------------------------------------
    # DOMAIN AGE
    # -----------------------------------------------------

    age = get_domain_age(domain)

    if age < 7:
        score += 35
        reasons.append(
            f"Very new domain ({age} days)"
        )

    elif age < 30:
        score += 20
        reasons.append(
            f"New domain ({age} days)"
        )

    elif age < 90:
        score += 10
        reasons.append(
            f"Recent domain ({age} days)"
        )

    # -----------------------------------------------------
    # ENTROPY
    # -----------------------------------------------------

    entropy = calculate_entropy(domain)

    if entropy > 4:
        score += 15
        reasons.append(
            f"High entropy ({entropy:.2f})"
        )

    # -----------------------------------------------------
    # RANDOM STRINGS
    # -----------------------------------------------------

    if contains_random_strings(domain):

        score += 10

        reasons.append(
            "Random-looking domain pattern"
        )

    # -----------------------------------------------------
    # NON-HTTPS
    # -----------------------------------------------------

    if parsed.scheme != "https":

        score += 10

        reasons.append("No HTTPS")

    # -----------------------------------------------------
    # SUBDOMAIN ABUSE
    # -----------------------------------------------------

    subdomain = tldextract.extract(url).subdomain

    if subdomain.count(".") >= 2:

        score += 10

        reasons.append(
            "Excessive subdomains"
        )

    # =====================================================
    # CLASSIFICATION
    # =====================================================

    if score >= 80:
        status = "Critical"

    elif score >= 50:
        status = "Suspicious"

    elif score >= 25:
        status = "Low Risk"

    else:
        status = "Likely Benign"

    return {
        "score": score,
        "status": status,
        "reasons": reasons,
        "domain_age_days": age,
        "entropy": round(entropy, 2),
        "brand_similarity": similarity,
    }

# =========================================================
# SEARCH ENGINE COLLECTION
# =========================================================

def fetch_search_results():

    if not TAVILY_API_KEY:
        raise Exception(
            "TAVILY_API_KEY missing"
        )

    url = "https://api.tavily.com/search"

    discovered = set()

    for query in SEARCH_QUERIES:

        print(f"[+] Searching: {query}")

        payload = {
            "api_key": TAVILY_API_KEY,
            "query": query,
            "search_depth": "advanced",
            "max_results": 30,
            "exclude_domains": EXCLUDED_DOMAINS,
        }

        try:

            response = session.post(
                url,
                json=payload,
                timeout=30,
            )

            if response.status_code != 200:

                print(
                    f"[!] Tavily error: "
                    f"{response.status_code}"
                )

                continue

            data = response.json()

            for result in data.get("results", []):

                target_url = result.get("url")

                if not target_url:
                    continue

                domain = normalize_domain(target_url)

                if is_official_domain(domain):
                    continue

                discovered.add(target_url)

            time.sleep(1)

        except Exception as e:

            print(
                f"[!] Query failed "
                f"({query}): {e}"
            )

    return list(discovered)

# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_urls(urls):

    findings = []

    for url in urls:

        try:

            risk = calculate_risk(url)

            findings.append({
                "url": url,
                "domain": normalize_domain(url),
                "status": risk["status"],
                "score": risk["score"],
                "brand_similarity":
                    risk["brand_similarity"],
                "domain_age_days":
                    risk["domain_age_days"],
                "entropy":
                    risk["entropy"],
                "reasons":
                    risk["reasons"],
                "timestamp":
                    datetime.datetime.utcnow().isoformat()
            })

        except Exception as e:

            print(
                f"[!] Failed analyzing "
                f"{url}: {e}"
            )

    findings.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return findings

# =========================================================
# SAVE RESULTS
# =========================================================

def save_results(results):

    with open(OUTPUT_FILE, "w") as f:

        json.dump(
            results,
            f,
            indent=4
        )

# =========================================================
# MAIN
# =========================================================

def main():

    print("[+] Starting phishing hunt")

    urls = fetch_search_results()

    print(f"[+] URLs discovered: {len(urls)}")

    results = analyze_urls(urls)

    save_results(results)

    critical = len([
        r for r in results
        if r["status"] == "Critical"
    ])

    suspicious = len([
        r for r in results
        if r["status"] == "Suspicious"
    ])

    print(f"[+] Critical findings : {critical}")
    print(f"[+] Suspicious findings : {suspicious}")
    print(f"[+] Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
