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
    
    # REDEFINED QUERIES: 
    # Targeting the specific patterns: typos, dashes, bn1, and cash.
    queries = [
        "bnidirect bni-direct login cash",
        "bn1direct bni-cash-management portal",
        "bnidrect login bni-direct-cash",
        "bni-direct-login indonesia dashboard"
    ]
    
    all_suspicious_urls = []
    exclude_list = [
        "bni.co.id", "facebook.com", "instagram.com", "twitter.com", 
        "x.com", "linkedin.com", "youtube.com", "tiktok.com"
    ]

    for q in queries:
        payload = {
            "api_key": TAVILY_API_KEY,
            "query": q,
            "search_depth": "advanced",
            "max_results": 40,
            "exclude_domains": exclude_list
        }
        
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    target_url = result['url'].lower()
                    
                    # Nuclear Filter for official domains
                    if "bni.co.id" in target_url:
                        continue
                        
                    all_suspicious_urls.append(result['url'])
            else:
                print(f"API Error for query '{q}': {response.status_code}")
        except Exception as e:
            print(f"Request failed for query '{q}': {e}")

    return list(set(all_suspicious_urls))

def analyze_urls(scraped_urls):
    results = []
    
    for url in scraped_urls:
        domain = url.split("//")[-1].split("/")[0].lower()
        
        # REDEFINED LOGIC: 
        # Specifically targeting the patterns you requested: 
        # bn1, dash combinations, and 'cash' keywords.
        status = "Safe"
        
        # Rule 1: Lookalike checks (bn1, bnid, direct, cash)
        # Added 'bn1' and 'cash' to the trigger list
        is_lookalike = any(x in domain for x in ["bni", "bn1", "bnid", "direct", "cash"])
        
        # Rule 2: Dash check (Commonly used in phishing to appear official)
        has_dash = "-" in domain
        
        # Rule 3: Functional keywords
        has_suspicious_path = any(kw in url.lower() for kw in ["login", "verif", "update", "secure", "portal"])

        # If it hits multiple red flags, it's Critical
        if (is_lookalike and has_dash) or (is_lookalike and has_suspicious_path):
            status = "Critical"
        elif is_lookalike or has_dash or has_suspicious_path:
            status = "Suspicious"
            
        results.append({
            "url": url,
            "domain": domain,
            "status": status,
            "timestamp": datetime.datetime.now().isoformat()
        })
        
    # Sort: Critical -> Suspicious -> Safe
    sorted_results = sorted(results, key=lambda x: (x['status'] != 'Critical', x['status'] != 'Suspicious'))
    
    return sorted_results[:100]

if __name__ == "__main__":
    print("Starting Redefined Phishing Hunt...")
    raw_urls = fetch_search_results()
    print(f"Total unique non-official URLs found: {len(raw_urls)}")
    
    threat_data = analyze_urls(raw_urls)
    
    with open("data.json", "w") as f:
        json.dump(threat_data, f, indent=4)
    print(f"Analysis complete. {len(threat_data)} items saved to data.json")
