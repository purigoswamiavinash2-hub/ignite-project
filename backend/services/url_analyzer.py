import re
from urllib.parse import urlparse
import math

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "click", "gq", "tk", "ml", "cf", 
    "rest", "vip", "icu", "sbs", "cfd", "fit", "monster", "cc", "su",
    "biz", "online", "site", "live", "link", "info", "zip", "mov"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", 
    "goo.gl", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "v.ht"
}

POPULAR_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", 
    "instagram", "netflix", "bankofamerica", "wellsfargo", "chase", 
    "binance", "coinbase", "sbi", "hdfc", "icici", "paytm", "phonepe"
]

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(text)]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return round(entropy, 2)

def analyze_url_structure(url: str) -> dict:
    # Ensure scheme
    formatted_url = url.strip()
    if not formatted_url.startswith(("http://", "https://")):
        formatted_url = "http://" + formatted_url

    parsed = urlparse(formatted_url)
    domain = parsed.netloc.split(":")[0].lower()
    path = parsed.path
    query = parsed.query

    reasons = []
    risk_points = 0

    # 1. IP Address check
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))
    if is_ip:
        risk_points += 35
        reasons.append("URL uses a raw IP address instead of a domain name")

    # 2. URL Shortener check
    is_shortener = domain in URL_SHORTENERS
    if is_shortener:
        risk_points += 20
        reasons.append(f"Uses known URL shortening service ({domain}) which masks destination")

    # 3. Suspicious TLD check
    tld = domain.split(".")[-1] if "." in domain else ""
    suspicious_tld = tld in SUSPICIOUS_TLDS
    if suspicious_tld:
        risk_points += 25
        reasons.append(f"Uses high-risk top-level domain (.{tld}) commonly associated with phishing")

    # 4. Subdomain count
    subdomains = domain.split(".")
    subdomain_count = max(0, len(subdomains) - 2)
    if subdomain_count >= 3:
        risk_points += 20
        reasons.append(f"Excessive subdomains ({subdomain_count}) detected")

    # 5. Lookalike / Typosquatting / Brand impersonation check
    lookalike_detected = False
    for brand in POPULAR_BRANDS:
        # Check if brand name appears in subdomains or path with suspicious characters
        if brand in domain and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.org"):
            # e.g., paypal-security-update.com or google.login-verify.xyz
            lookalike_detected = True
            risk_points += 35
            reasons.append(f"Potential brand impersonation detected for '{brand}' in domain name")
            break
        # Levenshtein / character replacement (e.g. g00gle, paypa1)
        modified_domain = domain.replace("0", "o").replace("1", "l").replace("3", "e").replace("@", "a")
        if brand in modified_domain and brand not in domain:
            lookalike_detected = True
            risk_points += 40
            reasons.append(f"Homograph/Typosquatting trick detected attempting to mimic '{brand}'")
            break

    # 6. Embedded credentials (@ symbol in URL)
    if "@" in parsed.netloc:
        risk_points += 30
        reasons.append("URL contains embedded '@' symbol to obfuscate real destination host")

    # 7. High entropy path/query
    full_string = path + query
    entropy = calculate_entropy(full_string)
    if len(full_string) > 20 and entropy > 4.5:
        risk_points += 15
        reasons.append(f"High randomness entropy ({entropy}) in URL path/query parameters")

    # 8. Excessive hyphens or symbols
    if domain.count("-") >= 3:
        risk_points += 15
        reasons.append("Domain contains excessive hyphens often used in phishing domains")

    risk_score = min(100, risk_points)

    return {
        "url": url,
        "domain": domain,
        "is_ip": is_ip,
        "is_shortener": is_shortener,
        "suspicious_tld": suspicious_tld,
        "subdomain_count": subdomain_count,
        "lookalike_detected": lookalike_detected,
        "entropy": entropy,
        "reputation_status": "Observed Structural Analysis",
        "risk_score": risk_score,
        "reasons": reasons
    }

def extract_urls(text: str) -> list:
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+|\b[a-zA-Z0-9.-]+\.(?:com|org|net|xyz|top|info|site|online|co|in|tech|app|xyz|club|work|io|me|dev)[^\s<>"]*'
    raw_urls = re.findall(url_pattern, text)
    cleaned_urls = []
    for u in raw_urls:
        cleaned = u.rstrip(".,;!?)")
        if cleaned and cleaned not in cleaned_urls:
            cleaned_urls.append(cleaned)
    return cleaned_urls
