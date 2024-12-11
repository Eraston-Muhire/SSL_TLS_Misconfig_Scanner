import argparse
import pyfiglet
from colorama import Fore, init
import os
from src.certificate import get_certificate_details, is_certificate_valid, is_certificate_self_signed
from src.protocols import check_supported_protocols
from src.ciphers import check_ciphers
from src.headers import check_headers
from src.api_scan import check_api_security
from src.utils import log_message, validate_target
from src.report import save_report, save_report_as_pdf

# Initialize Colorama for cross-platform color support
init(autoreset=True)

# Banner Function
def print_banner():
    banner_text = "SSL/TLS Scanner"
    font_style = "slant"
    banner = pyfiglet.figlet_format(banner_text, font=font_style)
    print(Fore.CYAN + banner)
    print(f"{Fore.CYAN}***************************************************************")
    print(f"{Fore.CYAN}* Comprehensive SSL/TLS Misconfiguration Scanner              *")
    print(f"{Fore.CYAN}* Version: 1.0.0                                              *")
    print(f"{Fore.CYAN}* Author: Eraston MUHIRE | Email: erastonmuhire@gmail.com     *")
    print(f"{Fore.CYAN}***************************************************************")
    print()

# Main Function
def main():
    # Print Banner
    print_banner()

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="SSL/TLS Misconfiguration Scanner: Identify common SSL/TLS configuration issues.",
        epilog="For more information, visit https://github.com"
    )
    parser.add_argument("--target", type=str, required=True, help="Target URL or IP address to scan.")
    parser.add_argument("--certificate", action="store_true", help="Run certificate validation checks.")
    parser.add_argument("--protocols", action="store_true", help="Run SSL/TLS protocol version checks.")
    parser.add_argument("--ciphers", action="store_true", help="Run weak/deprecated cipher checks.")
    parser.add_argument("--headers", action="store_true", help="Check for critical HTTP security headers.")
    parser.add_argument("--api", action="store_true", help="Scan API-specific SSL/TLS configurations and headers.")
    parser.add_argument("--output", type=str, help="Path to save the scan results (e.g., scan_results.json).")

    args = parser.parse_args()

    # Validate the target
    if not validate_target(args.target):
        log_message("error", "[!] Invalid target URL or IP address provided.")
        print(Fore.RED + "[!] Error: Invalid target URL or IP address provided.")
        return

    # Ensure at least one check is selected
    if not (args.certificate or args.protocols or args.ciphers or args.headers or args.api):
        log_message("error", "You must specify at least one scan option (eg: --certificate).")
        print(Fore.RED + "[!] Error: You must specify at least one scan option (eg: --certificate).")
        parser.print_help()
        return

    # Collect scan results here in json format ----------
    results = {}

    if args.certificate:
        print(Fore.YELLOW + "\n[Certificate Scan]")
        try:
            cert_details = get_certificate_details(args.target)
            print("Certificate Details:")
            for key, value in cert_details.items():
                print(f"  {key}: {value}")
            
            valid, message = is_certificate_valid(cert_details)
            print(f"Validity Check: {message}")
            
            if is_certificate_self_signed(cert_details):
                print("Warning: Certificate is self-signed.")
            else:
                print("Certificate is not self-signed.")
            results["certificate"] = {
                "details": cert_details,
                "validity": message,
                "self_signed": is_certificate_self_signed(cert_details),
            }
        except Exception as e:
            print(Fore.RED + f"Error during certificate scan: {e}")
            log_message("error", f"Error during Certificate Scan: {e}")
            results["certificate"] = {"error": str(e)}

    if args.protocols:
        print(Fore.YELLOW + "\n[Protocols Scan]")
        try:
            protocol_results = check_supported_protocols(args.target)
            print("Supported Protocols:")
            print(Fore.GREEN + " [+] Secure:")
            for protocol in protocol_results["secure"]:
                print(f"    - {protocol}")
            print(Fore.RED + " [-] Insecure:")
            for protocol in protocol_results["insecure"]:
                print(f"    - {protocol}")
            results["protocols"] = protocol_results
        except Exception as e:
            print(Fore.RED + f"[!] Error during protocols scan: {e}")
            log_message("error", f"Error during Protocols Scan: {e}")
            results["protocols"] = {"error": str(e)}

    if args.ciphers:
        print(Fore.YELLOW + "\n[Ciphers Scan]")
        try:
            cipher_results = check_ciphers(args.target)
            print("Supported Cipher Suites:")
            print(Fore.GREEN + " [+] Secure:")
            for cipher_info in cipher_results["secure"]:
                print(f"    - {cipher_info['cipher']}")
            print(Fore.RED + " [-] Insecure:")
            for cipher_info in cipher_results["insecure"]:
                print(f"    - {cipher_info['cipher']} (Issues: {', '.join(cipher_info['issues'])})")
            results["ciphers"] = cipher_results
        except Exception as e:
            print(Fore.RED + f"[!] Error during ciphers scan: {e}")
            log_message("error", f"Error during Ciphers Scan: {e}")
            results["ciphers"] = {"error": str(e)}

    if args.headers:
        print(Fore.YELLOW + "\n[Headers Scan]")
        try:
            headers_results = check_headers(f"https://{args.target}")
            print("HTTP Headers:")
            print(Fore.GREEN + " [+] Present:")
            for header in headers_results["present"]:
                print(f"    - {header}")
            print(Fore.RED + " [-] Missing:")
            for header in headers_results["missing"]:
                print(f"    - {header}")
            results["headers"] = headers_results
        except Exception as e:
            print(Fore.RED + f"[!] Error during headers scan: {e}")
            log_message("error", f"Error during Headers Scan: {e}")
            results["headers"] = {"error": str(e)}

    if args.api:
        print(Fore.YELLOW + "\n[API Scan]")
        try:
            api_results = check_api_security(f"https://{args.target}")
            print("API Security Findings:")
            print(Fore.GREEN + " [+] Headers:")
            print("  [+]  Present:")
            for header in api_results["headers"]["present"]:
                print(f"      - {header}")
            print(Fore.RED + "  [-]  Missing:")
            for header in api_results["headers"]["missing"]:
                print(f"      - {header}")
            print(Fore.GREEN + "  Protocols:")
            print("  [+] Secure:")
            for protocol in api_results["protocols"]["secure"]:
                print(f"      - {protocol}")
            print(Fore.RED + "   [-] Insecure:")
            for protocol in api_results["protocols"]["insecure"]:
                print(f"      - {protocol}")
            print(Fore.GREEN + "  Ciphers:")
            print("  [+]  Secure:")
            for cipher in api_results["ciphers"]["secure"]:
                print(f"      - {cipher['cipher']}")
            print(Fore.RED + "   [-] Insecure:")
            for cipher in api_results["ciphers"]["insecure"]:
                print(f"      - {cipher['cipher']} (Issues: {', '.join(cipher['issues'])})")
            results["api"] = api_results
        except Exception as e:
            print(Fore.RED + f"[!] Error during API scan: {e}")
            log_message("error", f"Error during API Scan: {e}")
            results["api"] = {"error": str(e)}

    # Save results to file if output is specified
    if args.output:
        try:
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
                print(Fore.YELLOW + f"[*] Directory '{output_dir}' created for saving the report.")
            else:
                print(Fore.YELLOW + f"[*] Report will be saved in the directory: '{output_dir or '.'}'")
            
            if args.output.endswith(".pdf"):
                save_report_as_pdf(results, args.output)
            else:
                save_report(results, args.output)

            print(Fore.GREEN + f"[+] Results saved to {args.output}")
            log_message("info", f"Results saved to {args.output}")
        except Exception as e:
            print(Fore.RED + f"[!] Error saving results to file: {e}")
            log_message("error", f"[!] Error saving results to file: {e}")


if __name__ == "__main__":
    main()
