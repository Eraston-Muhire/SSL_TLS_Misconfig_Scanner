import json
from typing import Any, Dict
from fpdf import FPDF
import os


def save_report(results: Dict[str, Any], file_path: str) -> None:
    """
    Saves the scan results to a file in JSON format.

    Args:
        results (dict): The consolidated scan results.
        file_path (str): Path to the output file.

    Raises:
        ValueError: If the file cannot be written.
    """
    try:
        # Validate directory
        output_dir = os.path.dirname(file_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(file_path, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Report saved successfully to {file_path}")
    except FileNotFoundError:
        raise ValueError(f"Invalid file path: {file_path}")
    except PermissionError:
        raise ValueError(f"Permission denied: Unable to write to {file_path}")
    except Exception as e:
        raise ValueError(f"Error saving report to {file_path}: {e}")


def save_report_as_pdf(results: dict, file_path: str) -> None:
    """
    Saves the scan results as a PDF file.

    Args:
        results (dict): The consolidated scan results.
        file_path (str): Path to the PDF file.

    Raises:
        ValueError: If the file cannot be written.
    """
    try:
        # Validate directory
        output_dir = os.path.dirname(file_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Title
        pdf.cell(200, 10, txt="SSL/TLS Misconfiguration Scan Report", ln=True, align="C")
        pdf.ln(10)

        # Add content
        for section, content in results.items():
            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(200, 10, txt=f"{section.capitalize()}:", ln=True)
            pdf.ln(5)
            pdf.set_font("Arial", size=10)
            if isinstance(content, dict):
                for key, value in content.items():
                    pdf.multi_cell(0, 10, txt=f"{key}: {value}")
            else:
                pdf.multi_cell(0, 10, txt=str(content))
            pdf.ln(10)

        # Save PDF
        pdf.output(file_path)
        print(f"PDF report saved successfully to {file_path}")
    except FileNotFoundError:
        raise ValueError(f"Invalid file path: {file_path}")
    except PermissionError:
        raise ValueError(f"Permission denied: Unable to write to {file_path}")
    except Exception as e:
        raise ValueError(f"Error saving PDF report to {file_path}: {e}")
