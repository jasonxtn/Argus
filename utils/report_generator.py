import csv
import os
import sys
import re
from colorama import Fore
import hashlib
import datetime

# Adding sys.path to import settings from the config directory
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from config import settings
from utils.util import clean_domain_input

# Utility function to sanitize and limit filename length
def safe_filename(s, max_length=255):
    s = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', s)
    return s[:max_length]

# Ensure the results directory exists (with domain subdirectory)
def ensure_results_directory(domain):
    results_dir = os.path.join(os.getcwd(), settings.RESULTS_DIR, domain)
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    return results_dir

# Function to generate base filename with modules used, with sanitized domain
def generate_base_filename(domain, modules_used):
    domain = clean_domain_input(domain)
    sanitized_domain = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)  # Replace invalid characters with underscores

    # Decide the module part of the filename
    if len(modules_used) == 1:
        module_part = modules_used[0]
    else:
        module_part = '_'.join(modules_used)
        if module_part in ['All_Infrastructure_Tools', 'All_Web_Intelligence_Tools', 'All_Security_Tools', 'BEAST_MODE']:
            module_part = module_part
        else:
            module_part = 'multiple_modules'

    # Include a timestamp
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # Construct the base filename
    base_filename = f"{sanitized_domain}_{module_part}_{timestamp}"

    # Sanitize and limit the filename length
    return safe_filename(base_filename)

# Function to write TXT report
def generate_txt_report(data, base_filename, results_dir):
    txt_file_path = os.path.join(results_dir, f"{base_filename}.txt")

    try:
        with open(txt_file_path, 'w', encoding='utf-8') as txt_file:
            for module_name, output in data.items():
                txt_file.write(f"=== {module_name} ===\n")
                txt_file.write(f"{output}\n\n")
        print(Fore.GREEN + f"TXT report generated successfully: {os.path.relpath(txt_file_path)}")
    except Exception as e:
        print(Fore.RED + f"Error generating TXT report: {e}")

# Function to write CSV report
def generate_csv_report(data, base_filename, results_dir):
    csv_file_path = os.path.join(results_dir, f"{base_filename}.csv")

    try:
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Module", "Output"])
            for module_name, output in data.items():
                # Replace newlines in output to keep CSV format clean
                clean_output = output.replace('\n', ' | ').replace('\r', '')
                writer.writerow([module_name, clean_output])
        print(Fore.GREEN + f"CSV report generated successfully: {os.path.relpath(csv_file_path)}")
    except Exception as e:
        print(Fore.RED + f"Error generating CSV report: {e}")

# Generate report with enhanced details based on settings
def generate_report(data, domain, modules_used):
    try:
        # Determine the base filename based on domain and used modules
        base_filename = generate_base_filename(domain, modules_used)
        results_dir = ensure_results_directory(domain)

        # Generate TXT report if enabled in settings
        if settings.EXPORT_SETTINGS.get("enable_txt_export", True):
            generate_txt_report(data, base_filename, results_dir)

        # Generate CSV report if enabled in settings
        if settings.EXPORT_SETTINGS.get("enable_csv_export", False):
            generate_csv_report(data, base_filename, results_dir)

    except Exception as e:
        print(Fore.RED + f"Error generating report: {e}")
