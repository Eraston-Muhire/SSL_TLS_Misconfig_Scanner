# SSL_TLS_Misconfig_Scanner
SSL_TLS_Misconfig_Scanner

Guidance 
-----------
python stscan.py --help


SSL/TLS Misconfiguration Scanner: Identify common SSL/TLS configuration issues.

options:
  -h, --help       show this help message and exit
  --target TARGET  Target URL or IP address to scan.
  --certificate    Run certificate validation checks.
  --protocols      Run SSL/TLS protocol version checks.
  --ciphers        Run weak/deprecated cipher checks.
  --headers        Check for critical HTTP security headers.
  --api            Scan API-specific SSL/TLS configurations and headers.
  --output OUTPUT  Path to save the scan results (e.g., scan_results.json).

Scanning target you want 
-------------------------

  usage: python stscan.py --target TARGET --certificate --protocols --ciphers --headers --api --output OUTPUT
