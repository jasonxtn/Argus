import csv
import os
import sys
import re
from colorama import Fore

# Adding sys.path to import settings from the config directory
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from config import settings
from utils.util import clean_domain_input

# Ensure the results directory exists
def ensure_results_directory():
    results_dir = os.path.join(os.getcwd(), settings.RESULTS_DIR)
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    return results_dir

# Function to generate base filename with modules used, with sanitized domain
def generate_base_filename(domain, modules_used):
    domain = clean_domain_input(domain)
    sanitized_domain = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)  # Replace invalid characters with underscores
    modules_str = "_".join([mod.replace(".py", "") for mod in modules_used])
    return f"{sanitized_domain}_{modules_str}"

# Function to write TXT report
def generate_txt_report(data, base_filename):
    results_dir = ensure_results_directory()
    txt_file_path = os.path.join(results_dir, f"{base_filename}.txt")

    try:
        with open(txt_file_path, 'w', encoding='utf-8') as txt_file:
            for key, value in data.items():
                txt_file.write(f"{key}: {value}\n")
        print(Fore.GREEN + f"TXT report generated successfully: results/{base_filename}.txt")
    except Exception as e:
        print(Fore.RED + f"Error generating TXT report: {e}")

# Function to write CSV report
def generate_csv_report(data, base_filename):
    results_dir = ensure_results_directory()
    csv_file_path = os.path.join(results_dir, f"{base_filename}.csv")

    try:
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Parameter", "Value"])
            for key, value in data.items():
                writer.writerow([key, value])
        print(Fore.GREEN + f"CSV report generated successfully: results/{base_filename}.csv")
    except Exception as e:
        print(Fore.RED + f"Error generating CSV report: {e}")

# Generate report with enhanced details based on settings
def generate_report(data, domain, modules_used):
    try:
        # Determine the base filename based on domain and used modules
        base_filename = generate_base_filename(domain, modules_used)

        # Generate TXT report if enabled in settings
        if settings.EXPORT_SETTINGS.get("enable_txt_export"):
            generate_txt_report(data, base_filename)

        # Generate CSV report if enabled in settings
        if settings.EXPORT_SETTINGS.get("enable_csv_export"):
            generate_csv_report(data, base_filename)

    except Exception as e:
        print(Fore.RED + f"Error generating report: {e}")
