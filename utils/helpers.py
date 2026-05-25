import urllib3
import requests
from urllib.parse import urlparse

# Disable SSL warnings for testing environments safely
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def validate_url(url: str) -> bool:
    """Validates if the provided string is a properly formatted HTTP/HTTPS URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except Exception:
        return False

def check_security_headers(url: str) -> dict:
    """
    Analyzes HTTP response headers to verify the presence of crucial security configurations.
    """
    important_headers = {
        "Strict-Transport-Security": "Missing HSTS Header (Risks Man-in-the-Middle attacks)",
        "X-Content-Type-Options": "Missing X-Content-Type-Options (Risks MIME-sniffing)",
        "X-Frame-Options": "Missing X-Frame-Options (Risks Clickjacking)",
        "Content-Security-Policy": "Missing Content-Security-Policy (Risks XSS/Injection)"
    }
    
    report = {"url": url, "secure": True, "findings": []}
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        
        for header, risk in important_headers.items():
            if header not in headers:
                report["secure"] = False
                report["findings"].append({"header": header, "status": "Missing", "risk_implication": risk})
            else:
                report["findings"].append({"header": header, "status": "Present", "value": headers[header]})
                
    except requests.exceptions.RequestException as e:
        report["secure"] = False
        report["findings"].append({"error": f"Failed to connect to the target: {str(e)}"})
        
    return report