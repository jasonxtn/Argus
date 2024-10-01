import re
import os
import json
import requests
import socket
from urllib.parse import urlparse
from colorama import Fore

# Function to validate domain names using regex
def validate_domain(domain):
    pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.'
        r'[A-Za-z]{2,6}$'
    )
    return pattern.match(domain) is not None

# Function to validate if a URL is properly formed
def validate_url(url):
    pattern = re.compile(
        r'^(https?:\/\/)?'  # http:// or https://
        r'([\da-z\.-]+)\.([a-z\.]{2,6})'  # domain name
        r'([\/\w \.-]*)*\/?$'  # path
    )
    return pattern.match(url) is not None

# Ensures a directory exists, creates it if not
def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# Read JSON configuration from a file
def read_json(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except Exception as e:
        print(Fore.RED + f"Error reading JSON file {file_path}: {e}")
        return {}

# Make an HTTP GET request with a timeout and return the response
def make_request(url, headers=None, timeout=10):
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error making request to {url}: {e}")
        return None

# Write the output to a file (used for saving results)
def write_to_file(file_path, data):
    try:
        with open(file_path, 'w') as file:
            file.write(data)
    except Exception as e:
        print(Fore.RED + f"Error writing to file {file_path}: {e}")

# Helper function to print formatted JSON data
def print_json(data):
    formatted_data = json.dumps(data, indent=4)
    print(Fore.CYAN + formatted_data)

# Function to convert a string to lowercase, with stripping and sanitizing input
def sanitize_input(input_str):
    return input_str.strip().lower()

# Simple function to check if a string is a valid IP address
def validate_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

# Simple log function to append to a log file
def log_message(log_file, message):
    try:
        with open(log_file, 'a') as f:
            f.write(f"{message}\n")
    except Exception as e:
        print(Fore.RED + f"Error writing log message: {e}")

# Function to check if API keys are configured
def check_api_configured(api_key_name):
    # Check if an environment variable or a key is set for the API
    return os.getenv(api_key_name) is not None

# Function to clean the domain input, whether it is a URL or domain
def clean_domain_input(domain_input):
    parsed_url = urlparse(domain_input)
    domain = parsed_url.netloc or parsed_url.path

    if domain.startswith('www.'):
        domain = domain[4:]

    return domain

# Function to resolve a domain to an IP address, with enhanced error handling
def resolve_to_ip(target):
    try:
        # Clean up and determine if input is a full URL or domain
        parsed_url = urlparse(target)
        domain = parsed_url.netloc if parsed_url.netloc else target

        # Strip 'www.' if present
        if domain.startswith('www.'):
            domain = domain[4:]

        # Resolve the domain to an IP address
        ip_address = socket.gethostbyname(domain)
        return ip_address

    except socket.gaierror:
        print(Fore.RED + f"[!] Error: Unable to resolve {target} to an IP address.")
        return None

# Function to clean up the URL and ensure it has the proper format
def clean_url(target):
    parsed_url = urlparse(target)

    # If no scheme (http/https) is provided, assume 'http://'
    if not parsed_url.scheme:
        target = f"http://{target}"
        parsed_url = urlparse(target)  # Re-parse after adding scheme

    # Clean up any trailing slashes from the path
    cleaned_url = parsed_url.scheme + "://" + parsed_url.netloc
    return cleaned_url

# Function to ensure domain input is a properly formatted URL
def ensure_url_format(domain_input):
    parsed_url = urlparse(domain_input)
    if not parsed_url.scheme:
        domain_input = f"http://{domain_input}"
    return domain_input
