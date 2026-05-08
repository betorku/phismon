import json
import datetime
from ddgs import DDGS

def fetch_search_results():
    # Make the query look like a normal human search to avoid DDG bot detection
    query = 'BNI Direct' 
    all_suspicious_urls = []
    
    try:
        with DDGS() as ddgs:
            # Removed safesearch param as it can sometimes trigger strict filters
            results = ddgs.text(
                query, 
                region='id-id', 
                max_results=30 # Increased to 30 to account for the official links we will drop
            )
            
            if results:
                for r in results:
                    url = r.get('href', '')
                    # The Developer Workaround: Manually exclude the official site in Python
                    if 'bni.co.id' not in url.lower() and url != '':
                        all_suspicious_urls.append(url)
            else:
                print("DuckDuckGo returned an empty response. IP might be temporarily rate-limited.")
                
    except Exception as e:
        print(f"Error during search: {e}")

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
    print("Starting Threat Crawler (DuckDuckGo Engine)...")
    raw_urls = fetch_search_results()
    
    print(f"Found {len(raw_urls)} external links after filtering. Analyzing threats...")
    threat_data = analyze_urls(raw_urls)
    
    with open("data.json", "w") as f:
        json.dump(threat_data, f, indent=4)
        
    print("Analysis complete. Data saved to data.json")
