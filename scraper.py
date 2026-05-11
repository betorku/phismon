import os
import json
import math
import re
import time
import socket
import datetime
import requests
import tldextract

from urllib.parse import urlparse
from rapidfuzz import fuzz
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================================================
# CONFIGURATION
# =========================================================

TAVILY_API_KEY = os.getenv("TAVILY_API_KEY")

OUTPUT_FILE = "data.json"

BRAND = "bni"

# Minimum score to save
MINIMUM_SCORE = 50

# Minimum brand similarity
MINIMUM_BRAND_SIMILARITY = 70

OFFICIAL_DOMAINS = [
    "bni.co.id",
]

EXCLUDED_DOMAINS = [
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "youtube.com",
    "twitter.com",
    "x.com",
    "tiktok.com",
    "wikipedia.org",
    "reddit.com",
    "bni.com",
    "bniconnect.com",
]

SEARCH_QUERIES = [
    "bni direct login",
    "bnidirect login",
    "bn1 direct login",
    "bni secure portal",
    "bni internet banking",
    "bni cash management",
    "bni reset password",
    "bni otp verification",
    "bni account verification",
    "bni login indonesia",
]

# =========================================================
# PHISHING INDICATORS
# =========================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "verifikasi",
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
    "payment",
    "reset",
    "blokir",
]

SUSPICIOUS_PATHS = [
    "/login",
    "/signin",
    "/verify",
    "/secure",
    "/auth",
    "/update",
    "/reset",
    "/otp",
    "/portal",
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
    "vip",
    "monster",
    "cloud",
]

PHISHING_PATTERNS = [
    "bn1",
    "bnii",
    "b-n-i",
    "bnid",
    "bnicash",
    "bnidirect",
    "bnisecure",
    "bni-login",
    "bni-secure",
]

SUSPICIOUS_HOSTING = [
    "cloudflare",
    "vercel",
    "netlify",
    "firebase",
    "github",
    "azure",
    "aws",
    "digitalocean",
    "oracle",
]

# =========================================================
# HTTP SESSION
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


def brand_similarity(domain):

    root = tldextract.extract(domain).domain

    score = max(
        fuzz.ratio(root, BRAND),
        fuzz.partial_ratio(root, BRAND),
        fuzz.token_sort_ratio(root, BRAND),
    )

    for pattern in PHISHING_PATTERNS:

        if pattern in root:
            score += 25

    return min(score, 100)


def contains_suspicious_keywords(url):

    url = url.lower()

    return [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url
    ]


def contains_suspicious_paths(url):

    url = url.lower()

    return [
        path
        for path in SUSPICIOUS_PATHS
        if path in url
    ]


def has_suspicious_tld(domain):

    suffix = tldextract.extract(domain).suffix

    return suffix in SUSPICIOUS_TLDS


def contains_random_strings(domain):

    return bool(
        re.search(r"[a-z0-9]{8,}", domain)
    )


def excessive_subdomains(url):

    subdomain = tldextract.extract(url).subdomain

    return subdomain.count(".") >= 2


def detect_ip_address_url(domain):

    return bool(
        re.match(
            r"^\d{1,3}(\.\d{1,3}){3}$",
            domain
        )
    )


def detect_suspicious_url_length(url):

    return len(url) > 120


# =========================================================
# HOSTING PROVIDER DETECTION
# =========================================================

def get_hosting_provider(domain):

    try:

        ip = socket.gethostbyname(domain)

        reverse = socket.gethostbyaddr(ip)[0].lower()

        for provider in SUSPICIOUS_HOSTING:

            if provider in reverse:
                return provider

    except Exception:
        pass

    return None

# =========================================================
# RISK ENGINE
# =========================================================

def calculate_risk(url):

    parsed = urlparse(url)

    domain = normalize_domain(url)

    score = 0

    reasons = []

    hosting_provider = None

    # -----------------------------------------------------
    # OFFICIAL DOMAIN
    # -----------------------------------------------------

    if is_official_domain(domain):

        return {
            "score": 0,
            "status": "Official",
            "reasons": ["Official domain"],
            "entropy": 0,
            "brand_similarity": 100,
            "hosting_provider": "Official"
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
    # PHISHING KEYWORDS
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
    # PHISHING PATHS
    # -----------------------------------------------------

    matched_paths = contains_suspicious_paths(url)

    if matched_paths:

        score += 20

        reasons.append(
            f"Suspicious paths: "
            f"{', '.join(matched_paths)}"
        )

    # -----------------------------------------------------
    # DASH ABUSE
    # -----------------------------------------------------

    if "-" in domain:

        score += 10

        reasons.append("Contains dash")

    # -----------------------------------------------------
    # SUSPICIOUS TLD
    # -----------------------------------------------------

    if has_suspicious_tld(domain):

        score += 20

        reasons.append("Suspicious TLD")

    # -----------------------------------------------------
    # HIGH ENTROPY
    # -----------------------------------------------------

    entropy = calculate_entropy(domain)

    if entropy > 4:

        score += 15

        reasons.append(
            f"High entropy ({entropy:.2f})"
        )

    # -----------------------------------------------------
    # RANDOM DOMAIN STRINGS
    # -----------------------------------------------------

    if contains_random_strings(domain):

        score += 10

        reasons.append(
            "Random-looking domain pattern"
        )

    # -----------------------------------------------------
    # NON HTTPS
    # -----------------------------------------------------

    if parsed.scheme != "https":

        score += 10

        reasons.append(
            "No HTTPS"
        )

    # -----------------------------------------------------
    # EXCESSIVE SUBDOMAINS
    # -----------------------------------------------------

    if excessive_subdomains(url):

        score += 10

        reasons.append(
            "Excessive subdomains"
        )

    # -----------------------------------------------------
    # IP ADDRESS URL
    # -----------------------------------------------------

    if detect_ip_address_url(domain):

        score += 25

        reasons.append(
            "Uses IP address instead of domain"
        )

    # -----------------------------------------------------
    # VERY LONG URL
    # -----------------------------------------------------

    if detect_suspicious_url_length(url):

        score += 10

        reasons.append(
            "Very long URL"
        )

    # -----------------------------------------------------
    # HOSTING PROVIDER
    # -----------------------------------------------------

    hosting_provider = get_hosting_provider(domain)

    if hosting_provider:

        score += 10

        reasons.append(
            f"Hosted on {hosting_provider}"
        )

    # =====================================================
    # FINAL CLASSIFICATION
    # =====================================================

    if score >= 80:
        status = "Critical"

    elif score >= 60:
        status = "Suspicious"

    else:
        status = "Low"

    return {
        "score": score,
        "status": status,
        "reasons": reasons,
        "entropy": round(entropy, 2),
        "brand_similarity": similarity,
        "hosting_provider": hosting_provider
    }

# =========================================================
# SEARCH COLLECTION
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

            # IMPORTANT:
            # Only recent indexed/search results
            "days": 30
        }

        try:

            response = session.post(
                url,
                json=payload,
                timeout=30
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
# ANALYSIS
# =========================================================

def analyze_urls(urls):

    findings = []

    for url in urls:

        try:

            domain = normalize_domain(url)

            risk = calculate_risk(url)

            # -------------------------------------------------
            # STRICT FILTERING
            # -------------------------------------------------

            if (
                risk["brand_similarity"]
                < MINIMUM_BRAND_SIMILARITY
            ):

                print(
                    f"[-] Low similarity skipped: "
                    f"{domain}"
                )

                continue

            if risk["score"] < MINIMUM_SCORE:

                print(
                    f"[-] Low score skipped: "
                    f"{domain}"
                )

                continue

            findings.append({
                "url": url,
                "domain": domain,
                "status": risk["status"],
                "score": risk["score"],
                "brand_similarity":
                    risk["brand_similarity"],
                "entropy":
                    risk["entropy"],
                "hosting_provider":
                    risk["hosting_provider"],
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
    print(f"[+] Total saved : {len(results)}")
    print(f"[+] Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
