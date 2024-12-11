import ssl
import socket
from typing import List, Dict

# Predefined list of weak ciphers and vulnerabilities
WEAK_CIPHERS = {
    "DES-CBC3-SHA": ["Triple DES (Deprecated)", "Vulnerable to SWEET32"],
    "ECDHE-RSA-DES-CBC3-SHA": ["Triple DES (Deprecated)", "Vulnerable to SWEET32"],
    "AES256-SHA": ["BEAST"],
    "AES128-SHA": ["BEAST"],
    "RC4-SHA": ["RC4 (Deprecated)"],
    "RC4-MD5": ["RC4 (Deprecated)"],
}

def get_default_ciphers() -> List[str]:
    """
    Retrieves a list of default ciphers from the OpenSSL implementation.

    Returns:
        list: A list of default cipher names.
    """
    context = ssl.create_default_context()
    return context.get_ciphers()

def check_ciphers(host: str, port: int = 443) -> Dict[str, List[Dict[str, List[str]]]]:
    """
    Checks supported cipher suites on the target server.

    Args:
        host (str): The target domain or IP address.
        port (int): The port to connect to (default: 443).

    Returns:
        dict: Supported ciphers categorized as secure or insecure with details.
    """
    ciphers = {
        "secure": [],
        "insecure": []
    }

    available_ciphers = get_default_ciphers()
    for cipher in available_ciphers:
        cipher_name = cipher.get("name")
        context = ssl.create_default_context()
        try:
            context.set_ciphers(cipher_name)
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    if cipher_name in WEAK_CIPHERS:
                        ciphers["insecure"].append({"cipher": cipher_name, "issues": WEAK_CIPHERS[cipher_name]})
                    else:
                        ciphers["secure"].append({"cipher": cipher_name, "issues": []})
        except ssl.SSLError:
            # if not supported by the server skip it and continue
            continue
        except Exception as e:
            raise ValueError(f"Error checking cipher {cipher_name}: {e}")

    return ciphers
