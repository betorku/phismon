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
    
    # 4 distinct queries to ensure we hit the 100-result quota
    queries = [
        "BNI Direct login",
        "bnidirect login",
        "bnidirect lookalike login"
        "bnidirect lookalike"
    ]
    
    all_suspicious_urls = []
    
    # This is the list we'll pass to the API
    exclude_list = [
        "bni.co.id", "facebook.com", "instagram.com", "twitter.com", 
        "x.com", "linkedin.com", "youtube.com", "tiktok.com"
    ]

    for q in queries:
        payload = {
            "api_key": TAVILY_API_KEY,
            "query": q,
            "search_depth": "advanced",
            "max_results": 40, # Getting enough raw data to filter down to 100
            "exclude_domains": exclude_list
        }
        
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    target_url = result['url'].lower()
                    
                    # THE NUCLEAR FILTER: Subdomain protection
                    if "bni.co.id" in target_url:
                        continue
                        
                    all_suspicious_urls.append(result['url'])
            else:
                print(f"API Error for query '{q}': {response.status_code}")
        except Exception as e:
            print(f"Request failed for query '{q}': {e}")

    # Remove duplicates
    return list(set(all_suspicious_urls))

def analyze_urls(scraped_urls):
    results = []
    
    for url in scraped_urls:
        domain = url.split("//")[-1].split("/")[0].lower()
        
        # Scoring logic to catch "bnidret", "bni-direct", etc.
        status = "Safe"
        
        # Logic: Flag domains that look like BNI but aren't official
        is_lookalike = any(x in domain for x in ["bni", "bn1", "bnid", "direct"])
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
    
    # Return exactly 100 results as requested
    return sorted_results[:100]

if __name__ == "__main__":
    print("Starting Advanced Threat Scraper (100-Result Mode)...")
    raw_urls = fetch_search_results()
    print(f"Total unique non-official URLs found: {len(raw_urls)}")
    
    threat_data = analyze_urls(raw_urls)
    
    with open("data.json", "w") as f:
        json.dump(threat_data, f, indent=4)
    print(f"Analysis complete. {len(threat_data)} items saved to data.json")
