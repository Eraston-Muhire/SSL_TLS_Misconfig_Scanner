import ssl
import socket
from typing import List, Dict


def check_supported_protocols(host: str, port: int = 443) -> Dict[str, List[str]]:
    """
    Checks supported SSL/TLS protocols on the target server.

    Args:
        host (str): The target domain or IP address.
        port (int): The port to connect to (default: 443).

    Returns:
        dict: Supported protocols categorized as secure or insecure.
    """
    protocols = {
        "secure": [],
        "insecure": []
    }

    # Mapping of SSLContext versions to human-readable names
    protocol_map = {
        ssl.TLSVersion.TLSv1: "TLS 1.0 (Deprecated)",
        ssl.TLSVersion.TLSv1_1: "TLS 1.1 (Deprecated)",
        ssl.TLSVersion.TLSv1_2: "TLS 1.2 (Secure)",
        ssl.TLSVersion.TLSv1_3: "TLS 1.3 (Secure)",
    }

    # Check modern TLS versions
    for version, name in protocol_map.items():
        try:
            context = ssl.create_default_context()
            context.maximum_version = version
            context.minimum_version = version
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    if "Deprecated" in name:
                        protocols["insecure"].append(name)
                    else:
                        protocols["secure"].append(name)
        except (ssl.SSLError, ValueError):
            continue
        except Exception as e:
            raise ValueError(f"Error checking protocol {name}: {e}")

    # Check for SSLv2 and SSLv3 using PROTOCOL_SSLv23
    legacy_protocols = {
        "SSLv2 (Deprecated)": ssl.PROTOCOL_SSLv23,  # Proxy for SSLv2
        "SSLv3 (Deprecated)": ssl.PROTOCOL_SSLv23,  # Proxy for SSLv3
    }

    for version_name, protocol in legacy_protocols.items():
        try:
            context = ssl.SSLContext(protocol)
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
            if version_name == "SSLv2 (Deprecated)":
                context.options |= ssl.OP_NO_SSLv3  # Disable SSLv3 for SSLv2 check
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    protocols["insecure"].append(version_name)
        except (ssl.SSLError, ValueError):
            continue
        except Exception as e:
            raise ValueError(f"Error checking legacy protocol {version_name}: {e}")

    return protocols
