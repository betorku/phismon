import json
import datetime
import requests
import os

TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY")

def fetch_search_results():
    if not TAVILY_API_KEY:
        print("Error: TAVILY_API_KEY is missing!")
        return []

    url = "https://api.tavily.com/search"
    
    # We broaden the query to look for "action-oriented" phishing terms
    # Using terms like 'update', 'verifikasi', and 'maintenance' 
    # which are commonly used in Indonesian banking phish kits.
    queries = [
        "BNI Direct login update verifikasi",
        "BNI Direct maintenance login Indonesia",
        "bnidirect lookalike login"
    ]
    
    all_suspicious_urls = []
   # Still passing these to the API to reduce initial noise
    exclude_list = [
        "bni.co.id", "bnidirect.bni.co.id", "facebook.com", 
        "instagram.com", "twitter.com", "x.com", "linkedin.com"
    ]

    for q in queries:
        payload = {
            "api_key": TAVILY_API_KEY,
            "query": q,
            "search_depth": "advanced",
            "max_results": 25,
            "exclude_domains": social_media_and_official
        }
        
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    all_suspicious_urls.append(result['url'])
        except Exception as e:
            print(f"Request failed for query '{q}': {e}")

    # Remove duplicates
    return list(set(all_suspicious_urls))

def analyze_urls(scraped_urls):
    results = []
    
    for url in scraped_urls:
        domain = url.split("//")[-1].split("/")[0].lower()
        
        # IMPROVED LOGIC: Lookalike Detection
        # This catches "bnidret", "bni-direct", "bni.login", etc.
        status = "Safe"
        
        # Rule 1: Direct name matching or common typos
        is_lookalike = any(x in domain for x in ["bni", "bn1", "bnid", "direct"])
        
        # Rule 2: Suspicious keywords in the URL path
        has_suspicious_path = any(kw in url.lower() for kw in ["login", "verif", "update", "secure"])

        if is_lookalike and has_suspicious_path:
            status = "Critical"
        elif is_lookalike or has_suspicious_path:
            status = "Suspicious"
            
        results.append({
            "url": url,
            "domain": domain,
            "status": status,
            "timestamp": datetime.datetime.now().isoformat()
        })
        
    # Sort results so Critical ones appear at the top
    sorted_results = sorted(results, key=lambda x: (x['status'] != 'Critical', x['status'] != 'Suspicious'))
    return sorted_results[:50]

if __name__ == "__main__":
    print("Starting Advanced Threat Scraper...")
    raw_urls = fetch_search_results()
    print(f"Total unique URLs found: {len(raw_urls)}")
    
    threat_data = analyze_urls(raw_urls)
    
    with open("data.json", "w") as f:
        json.dump(threat_data, f, indent=4)
    print("Analysis complete.")
