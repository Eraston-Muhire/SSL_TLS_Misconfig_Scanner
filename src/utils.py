import re
import logging
from typing import Any, Dict

# Initialize logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def log_message(level: str, message: str) -> None:
    """
    Logs a message with the specified log level.

    Args:
        level (str): The log level (e.g., 'info', 'error').
        message (str): The message to log.
    """
    levels = {
        "info": logging.info,
        "warning": logging.warning,
        "error": logging.error,
        "debug": logging.debug,
    }
    log_function = levels.get(level.lower(), logging.info)
    log_function(message)

def format_results(results: Dict[str, Any]) -> str:
    """
    Formats scan results into a readable string for terminal output.

    Args:
        results (dict): The results to format.

    Returns:
        str: Formatted results as a string.
    """
    formatted = []
    for key, value in results.items():
        formatted.append(f"{key.capitalize()}:\n")
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                formatted.append(f"  {sub_key}: {sub_value}\n")
        else:
            formatted.append(f"  {value}\n")
    return "".join(formatted)

def validate_target(target: str) -> bool:
    """
    Validates the target URL or IP address.

    Args:
        target (str): The target to validate.

    Returns:
        bool: True if the target is valid, False otherwise.
    """
    url_pattern = re.compile(
        r"^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$"
    )
    ip_pattern = re.compile(
        r"^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$"
    )
    if url_pattern.match(target) or ip_pattern.match(target):
        return True
    return False
