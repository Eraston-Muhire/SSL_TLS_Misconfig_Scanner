import requests
from typing import Dict, List

# List of critical headers to check
CRITICAL_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "Content-Security-Policy": "Prevents content injection attacks",
    "X-Content-Type-Options": "Mitigates MIME-sniffing vulnerabilities",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-XSS-Protection": "Mitigates cross-site scripting (XSS) attacks"
}

def check_headers(url: str) -> Dict[str, List[str]]:
    """
    Checks for the presence of critical HTTP headers on the target URL.

    Args:
        url (str): The target URL.

    Returns:
        dict: Dictionary categorizing headers as present or missing.
    """
    headers_status = {
        "present": [],
        "missing": []
    }

    try:
        response = requests.head(url, timeout=10)
        response_headers = response.headers

        for header, description in CRITICAL_HEADERS.items():
            if header in response_headers:
                headers_status["present"].append(f"{header}: {description}")
            else:
                headers_status["missing"].append(f"{header}: {description}")

    except requests.RequestException as e:
        raise ValueError(f"Error fetching headers from {url}: {e}")

    return headers_status
