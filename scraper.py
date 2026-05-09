import json
import datetime
import requests
import os
import math
import re
import whois
import tldextract

from urllib.parse import urlparse
from rapidfuzz import fuzz

# =========================================================
# CONFIG
# =========================================================

TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY")

BRAND = "bni"

OFFICIAL_DOMAINS = [
    "bni.co.id"
]

EXCLUDED_DOMAINS = [
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "youtube.com",
    "tiktok.com"
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
    "webscr",
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
]

# =========================================================
# HELPERS
# =========================================================

def normalize_domain(url):
    """
    Extract root domain cleanly
    Example:
    https://secure.bni-login.xyz/path
    -> bni-login.xyz
    """
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()


def calculate_entropy(text):
    """
    Detect random-looking phishing domains
    """
    if not text:
        return 0

    prob = [float(text.count(c)) / len(text) for c in set(text)]

    return -sum(p * math.log(p, 2) for p in prob)


def get_domain_age(domain):
    """
    Get WHOIS age in days
    """
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age = (datetime.datetime.utcnow() - creation_date).days
            return age

    except Exception:
        pass

    return 9999


def is_official_domain(domain):
    return any(domain.endswith(d) for d in OFFICIAL_DOMAINS)


def brand_similarity(domain):
    """
    Fuzzy matching against BNI
    """

    root = tldextract.extract(domain).domain

    score = fuzz.ratio(root, BRAND)

    # Handle common phishing tricks
    phishing_patterns = [
        "bn1",
        "bnii",
        "bnii",
        "b-n-i",
        "bnid",
        "bnicash",
        "bnidirect",
    ]

    for p in phishing_patterns:
        if p in root:
            score += 25

    return min(score, 100)


def contains_suspicious_keywords(url):
    url = url.lower()
    return [k for k in SUSPICIOUS_KEYWORDS if k in url]


def has_suspicious_tld(domain):
    suffix = tldextract.extract(domain).suffix
    return suffix in SUSPICIOUS_TLDS


def contains_random_strings(domain):
    """
    Detect random phishing-like strings
    Example:
    bni-login-x82hja.com
    """
    return bool(re.search(r"[a-z0-9]{8,}", domain))


# =========================================================
# THREAT SCORING
# =========================================================

def calculate_risk(url):

    parsed = urlparse(url)
    domain = normalize_domain(url)

    score = 0
    reasons = []

    # -----------------------------------------------------
    # Official domain check
    # -----------------------------------------------------

    if is_official_domain(domain):
        return {
            "score": 0,
            "status": "Official",
            "reasons": ["Official domain"]
        }

    # -----------------------------------------------------
    # Brand similarity
    # -----------------------------------------------------

    similarity = brand_similarity(domain)

    if similarity >= 90:
        score += 45
        reasons.append(f"Very high brand similarity ({similarity})")

    elif similarity >= 70:
        score += 30
        reasons.append(f"High brand similarity ({similarity})")

    elif similarity >= 50:
        score += 15
        reasons.append(f"Medium brand similarity ({similarity})")

    # -----------------------------------------------------
    # Dash abuse
    # -----------------------------------------------------

    if "-" in domain:
        score += 10
        reasons.append("Contains dash")

    # -----------------------------------------------------
    # Suspicious keywords
    # -----------------------------------------------------

    keywords = contains_suspicious_keywords(url)

    if keywords:
        keyword_score = min(len(keywords) * 10, 30)
        score += keyword_score
        reasons.append(f"Suspicious keywords: {', '.join(keywords)}")

    # -----------------------------------------------------
    # Suspicious TLD
    # -----------------------------------------------------

    if has_suspicious_tld(domain):
        score += 20
        reasons.append("Suspicious TLD")

    # -----------------------------------------------------
    # Young domain
    # -----------------------------------------------------

    age = get_domain_age(domain)

    if age < 7:
        score += 35
        reasons.append(f"Very new domain ({age} days old)")

    elif age < 30:
        score += 20
        reasons.append(f"New domain ({age} days old)")

    elif age < 90:
        score += 10
        reasons.append(f"Recent domain ({age} days old)")

    # -----------------------------------------------------
    # Entropy/randomness
    # -----------------------------------------------------

    entropy = calculate_entropy(domain)

    if entropy > 4:
        score += 15
        reasons.append(f"High entropy ({entropy:.2f})")

    # -----------------------------------------------------
    # Random strings
    # -----------------------------------------------------

    if contains_random_strings(domain):
        score += 10
        reasons.append("Random-looking string")

    # -----------------------------------------------------
    # HTTP only
    # -----------------------------------------------------

    if parsed.scheme != "https":
        score += 10
        reasons.append("Not using HTTPS")

    # -----------------------------------------------------
    # Long subdomain chains
    # -----------------------------------------------------

    subdomain = tldextract.extract(url).subdomain

    if subdomain.count(".") >= 2:
        score += 10
        reasons.append("Excessive subdomains")

    # =====================================================
    # FINAL CLASSIFICATION
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
# SEARCH
# =========================================================

def fetch_search_results():

    if not TAVILY_API_KEY:
        print("TAVILY_API_KEY missing")
        return []

    url = "https://api.tavily.com/search"

    discovered = set()

    for query in SEARCH_QUERIES:

        payload = {
            "api_key": TAVILY_API_KEY,
            "query": query,
            "search_depth": "advanced",
            "max_results": 50,
            "exclude_domains": EXCLUDED_DOMAINS,
        }

        try:

            response = requests.post(
                url,
                json=payload,
                timeout=20
            )

            if response.status_code != 200:
                print(f"Search error: {response.status_code}")
                continue

            data = response.json()

            for result in data.get("results", []):

                target_url = result.get("url", "")

                if not target_url:
                    continue

                domain = normalize_domain(target_url)

                if is_official_domain(domain):
                    continue

                discovered.add(target_url)

        except Exception as e:
            print(f"Query failed [{query}]: {e}")

    return list(discovered)


# =========================================================
# MAIN ANALYSIS
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
                "brand_similarity": risk["brand_similarity"],
                "domain_age_days": risk["domain_age_days"],
                "entropy": risk["entropy"],
                "reasons": risk["reasons"],
                "timestamp": datetime.datetime.utcnow().isoformat()
            })

        except Exception as e:
            print(f"Analysis failed for {url}: {e}")

    findings.sort(key=lambda x: x["score"], reverse=True)

    return findings


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    print("[+] Starting phishing hunt...")

    urls = fetch_search_results()

    print(f"[+] URLs collected: {len(urls)}")

    results = analyze_urls(urls)

    with open("data.json", "w") as f:
        json.dump(results, f, indent=4)

    critical = len([x for x in results if x["status"] == "Critical"])

    suspicious = len([x for x in results if x["status"] == "Suspicious"])

    print(f"[+] Critical findings : {critical}")
    print(f"[+] Suspicious findings : {suspicious}")

    print("[+] Results saved to data.json")
