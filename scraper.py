import json
import datetime
from ddgs import DDGS

def fetch_search_results():
    # Using a natural search query to prevent DuckDuckGo bot detection
    query = 'BNI Direct' 
    all_suspicious_urls = []
    
    try:
        with DDGS() as ddgs:
            # Fetching 70 results to ensure we have enough after filtering official sites
            results = ddgs.text(
                query, 
                region='id-id', 
                max_results=70 
            )
            
            if results:
                for r in results:
                    url = r.get('href', '')
                    
                    # Python-level filter: Exclude official domains to isolate the threats
                    if 'bni.co.id' not in url.lower() and url != '':
                        all_suspicious_urls.append(url)
            else:
                print("DuckDuckGo returned an empty response. Possible rate limit.")
                
    except Exception as e:
        print(f"Error during search: {e}")

    # Enforce a strict maximum of 50 URLs for the final dashboard
    return all_suspicious_urls[:50]

def analyze_urls(scraped_urls):
    results = []
    target_brand = "bni"
    
    for url in scraped_urls:
        # Extract just the root domain from the URL for analysis
        domain = url.split("//")[-1].split("/")[0]
        
        # Threat logic scoring
        status = "Safe"
        if target_brand in domain.lower():
            status = "Critical" # E.g., bni-direct-login.com
        elif any(kw in domain.lower() for kw in ["login", "secure", "portal", "auth"]):
            status = "Suspicious" # E.g., secure-banking-portal.net
            
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
    
    # Save output to JSON for the dashboard
    with open("data.json", "w") as f:
        json.dump(threat_data, f, indent=4)
        
    print("Analysis complete. Data saved to data.json")
