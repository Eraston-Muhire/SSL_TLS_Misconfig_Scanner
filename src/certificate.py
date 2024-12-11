import ssl
import socket
from datetime import datetime
from typing import Dict, Tuple

def get_certificate_details(host: str, port: int = 443) -> Dict[str, str]:
    """
    Retrieves SSL/TLS certificate details from the target host.
    
    Args:
        host (str): The target domain or IP address.
        port (int): The port to connect to (default: 443).
    
    Returns:
        dict: Certificate details including issuer, subject, validity, etc.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        raise ValueError(f"Unable to retrieve certificate details for {host}: {e}")
    
    details = {
        "issuer": dict(x[0] for x in cert["issuer"]),
        "subject": dict(x[0] for x in cert["subject"]),
        "valid_from": cert["notBefore"],
        "valid_to": cert["notAfter"],
    }
    return details

def is_certificate_valid(cert: Dict[str, str]) -> Tuple[bool, str]:
    """
    Checks if the certificate is valid based on its validity period.
    
    Args:
        cert (dict): Certificate details.
    
    Returns:
        tuple: (bool, str) indicating if the certificate is valid and a message.
    """
    try:
        valid_from = datetime.strptime(cert["valid_from"], "%b %d %H:%M:%S %Y %Z")
        valid_to = datetime.strptime(cert["valid_to"], "%b %d %H:%M:%S %Y %Z")
        now = datetime.utcnow()
        
        if now < valid_from:
            return False, f"Certificate is not yet valid. Starts on {cert['valid_from']}."
        if now > valid_to:
            return False, f"Certificate has expired. Expired on {cert['valid_to']}."
        
        return True, "Certificate is valid."
    except Exception as e:
        raise ValueError(f"Error validating certificate: {e}")

def is_certificate_self_signed(cert: Dict[str, str]) -> bool:
    """
    Checks if the certificate is self-signed.
    
    Args:
        cert (dict): Certificate details.
    
    Returns:
        bool: True if the certificate is self-signed, False otherwise.
    """
    try:
        return cert["issuer"] == cert["subject"]
    except KeyError as e:
        raise ValueError(f"Error checking self-signed status: {e}")
