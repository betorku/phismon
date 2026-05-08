import json
import datetime
from duckduckgo_search import DDGS

def fetch_search_results():
    # Target keyword and excluding the official domain
    query = '"BNI Direct" -site:bni.co.id'
    all_suspicious_urls = []
    
    try:
        # DDGS searches without needing an API key
        with DDGS() as ddgs:
            # region='id-id' targets Indonesia, max_results limits to top 20
            results = ddgs.text(
                query, 
                region='id-id', 
                safesearch='off', 
                max_results=20
            )
            
            for r in results:
                # duckduckgo_search returns a dictionary with 'href' for the URL
                all_suspicious_urls.append(r['href'])
                
    except Exception as e:
        print(f"Error during search: {e}")

    return all_suspicious_urls

def analyze_urls(scraped_urls):
    results = []
    target_brand = "bni"
    
    for url in scraped_urls:
        domain = url.split("//")[-1].split("/")[0]
        
        # Threat logic
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
    print("Starting Threat Crawler (DuckDuckGo Engine)...")
    raw_urls = fetch_search_results()
    
    print(f"Found {len(raw_urls)} external links. Analyzing threats...")
    threat_data = analyze_urls(raw_urls)
    
    with open("data.json", "w") as f:
        json.dump(threat_data, f, indent=4)
        
    print("Analysis complete. Data saved to data.json")
