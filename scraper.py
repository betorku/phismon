import json
import datetime
import requests
import os

# Pulls the key securely from GitHub Secrets
TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY")

def fetch_search_results():
    if not TAVILY_API_KEY:
        print("Error: TAVILY_API_KEY is missing!")
        return []

    url = "https://api.tavily.com/search"
    payload = {
        "api_key": TAVILY_API_KEY,
        "query": "BNI Direct",
        "search_depth": "advanced", # Pulls higher quality, deeper web results
        "include_answer": False,
        "include_images": False,
        "include_raw_content": False,
        "max_results": 50,
        # Tavily explicitly strips these out before returning data to us
        "exclude_domains": ["bni.co.id", "www.bni.co.id"] 
    }
    
    all_suspicious_urls = []
    
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            data = response.json()
            for result in data.get('results', []):
                all_suspicious_urls.append(result['url'])
        else:
            print(f"Tavily API Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")

    return all_suspicious_urls

def analyze_urls(scraped_urls):
    results = []
    target_brand = "bni"
    
    for url in scraped_urls:
        domain = url.split("//")[-1].split("/")[0]
        
        status = "Safe"
        if target_brand in domain.lower():
            status = "Critical" 
        elif any(kw in domain.lower() for kw in ["login", "secure", "portal", "auth"]):
            status = "Suspicious" 
            
        results.append({
            "url": url,
            "domain": domain,
            "status": status,
            "timestamp": datetime.datetime.now().isoformat()
        })
        
    return results

if __name__ == "__main__":
    print("Starting Threat Crawler (Tavily Engine)...")
    raw_urls = fetch_search_results()
    
    print(f"Found {len(raw_urls)} external links. Analyzing threats...")
    threat_data = analyze_urls(raw_urls)
    
    with open("data.json", "w") as f:
        json.dump(threat_data, f, indent=4)
        
    print("Analysis complete. Data saved to data.json")
