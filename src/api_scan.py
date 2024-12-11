import requests
from src.protocols import check_supported_protocols
from src.ciphers import check_ciphers

# Critical API-specific headers
API_HEADERS = {
    "Access-Control-Allow-Origin": "CORS: Specifies allowed origins for cross-domain requests",
    "Access-Control-Allow-Methods": "CORS: Specifies allowed HTTP methods for cross-domain requests",
    "Access-Control-Allow-Headers": "CORS: Specifies allowed headers for cross-domain requests"
}

def check_api_headers(url: str) -> dict:
    """
    Checks API-specific HTTP headers on the target URL.

    Args:
        url (str): The target API endpoint.

    Returns:
        dict: Dictionary categorizing headers as present or missing.
    """
    headers_status = {
        "present": [],
        "missing": []
    }

    try:
        response = requests.options(url, timeout=10)
        response_headers = response.headers

        for header, description in API_HEADERS.items():
            if header in response_headers:
                headers_status["present"].append(f"{header}: {description}")
            else:
                headers_status["missing"].append(f"{header}: {description}")

    except requests.RequestException as e:
        raise ValueError(f"Error fetching API headers from {url}: {e}")

    return headers_status

def check_api_security(url: str) -> dict:
    """
    Combines SSL/TLS checks and API header checks for the target API.

    Args:
        url (str): The target API base URL or endpoint.

    Returns:
        dict: Comprehensive security findings for the API.
    """
    findings = {
        "headers": check_api_headers(url),
        "protocols": check_supported_protocols(url.replace("https://", "").split("/")[0]),
        "ciphers": check_ciphers(url.replace("https://", "").split("/")[0])
    }
    return findings
