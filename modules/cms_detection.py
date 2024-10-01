import sys, os
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, init
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_url, make_request, validate_url


init(autoreset=True)
console = Console()


CMS_SIGNATURES = {
    "WordPress": {
        "meta_generator": "WordPress",
        "html_comments": "wp-content",
        "path_indicators": ["/wp-content/", "/wp-includes/", "/wp-json/"]
    },
    "Joomla": {
        "meta_generator": "Joomla",
        "html_comments": "Joomla!",
        "path_indicators": ["/components/", "/modules/", "/templates/", "/media/"]
    },
    "Drupal": {
        "meta_generator": "Drupal",
        "html_comments": "Drupal",
        "path_indicators": ["/sites/", "/core/", "/misc/", "/profiles/"]
    },
    "Magento": {
        "meta_generator": "Magento",
        "html_comments": "Mage",
        "path_indicators": ["/static/frontend/", "/media/catalog/"]
    },
    "Prestashop": {
        "meta_generator": "PrestaShop",
        "html_comments": "PrestaShop",
        "path_indicators": ["/themes/", "/modules/", "/img/", "/js/"]
    },
    "OpenCart": {
        "meta_generator": "OpenCart",
        "html_comments": "OpenCart",
        "path_indicators": ["/catalog/view/", "/admin/controller/", "/system/storage/"]
    },
    "Shopify": {
        "meta_generator": "Shopify",
        "html_comments": "Shopify",
        "path_indicators": ["/cdn.shopify.com", "/assets/"]
    },
    "TYPO3": {
        "meta_generator": "TYPO3",
        "html_comments": "TYPO3",
        "path_indicators": ["/typo3conf/", "/typo3_src/", "/typo3temp/"]
    },
    "Ghost": {
        "meta_generator": "Ghost",
        "html_comments": "Ghost",
        "path_indicators": ["/ghost/", "/content/"]
    },
    "ExpressionEngine": {
        "meta_generator": "ExpressionEngine",
        "html_comments": "ExpressionEngine",
        "path_indicators": ["/themes/ee/"]
    },
    "Wix": {
        "meta_generator": "Wix.com",
        "html_comments": "wix.com",
        "path_indicators": ["/wixpress/"]
    },
    "Weebly": {
        "meta_generator": "Weebly",
        "html_comments": "weebly",
        "path_indicators": ["/files/theme/"]
    },
    "Squarespace": {
        "meta_generator": "Squarespace",
        "html_comments": "squarespace",
        "path_indicators": ["/config.json", "/universal/"]
    },
    "Blogger": {
        "meta_generator": "blogger",
        "html_comments": "blogger",
        "path_indicators": ["/feeds/posts/"]
    },
    "Bitrix": {
        "meta_generator": "Bitrix",
        "html_comments": "bitrix",
        "path_indicators": ["/bitrix/"]
    },
    "Django CMS": {
        "meta_generator": "Django",
        "html_comments": "django",
        "path_indicators": ["/static/django/"]
    },
    "Craft CMS": {
        "meta_generator": "Craft CMS",
        "html_comments": "craftcms",
        "path_indicators": ["/craft/"]
    },
    "Umbraco": {
        "meta_generator": "Umbraco",
        "html_comments": "umbraco",
        "path_indicators": ["/umbraco/"]
    },
    "MODX": {
        "meta_generator": "MODX",
        "html_comments": "modx",
        "path_indicators": ["/manager/assets/"]
    },
    "Contao": {
        "meta_generator": "Contao",
        "html_comments": "contao",
        "path_indicators": ["/contao/"]
    }
}

def banner():
    console.print(Fore.WHITE + """
    =============================================
            Argus - CMS Enumeration Module
    =============================================
    """)

def detect_cms_from_meta(soup):
    """Check for CMS signatures in meta tags"""
    for cms, details in CMS_SIGNATURES.items():
        meta_tag = soup.find("meta", {"name": "generator"})
        if meta_tag and details["meta_generator"] in meta_tag.get("content", ""):
            return cms
    return None

def detect_cms_from_html_comments(html_content):
    """Check for CMS signatures in HTML comments"""
    for cms, details in CMS_SIGNATURES.items():
        if details["html_comments"] in html_content:
            return cms
    return None

def detect_cms_from_paths(url):
    """Check for CMS-specific paths"""
    for cms, details in CMS_SIGNATURES.items():
        for path in details["path_indicators"]:
            test_url = f"{url.rstrip('/')}{path}"
            response = make_request(test_url)
            if response and response.status_code == 200:
                return cms
    return None

def enumerate_cms(target):
    try:
        
        cleaned_url = clean_url(target)
        if not validate_url(cleaned_url):
            console.print(Fore.RED + f"[!] Invalid URL: {target}")
            return None

        
        response = make_request(cleaned_url)
        if not response or response.status_code != 200:
            console.print(Fore.RED + f"[!] Error: Received status code {response.status_code}")
            return None

        soup = BeautifulSoup(response.content, 'html.parser')
        html_content = response.text

        
        detected_cms = detect_cms_from_meta(soup)
        if detected_cms:
            return detected_cms

        detected_cms = detect_cms_from_html_comments(html_content)
        if detected_cms:
            return detected_cms

        detected_cms = detect_cms_from_paths(cleaned_url)
        if detected_cms:
            return detected_cms

        return "Unknown CMS"
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error: {e}")
        return None

def display_cms_result(cms_name):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("CMS Detection Result", style="cyan", justify="left")
    table.add_row(cms_name)
    console.print(table)

def main(target):
    banner()
    console.print(Fore.WHITE + f"[*] Enumerating CMS for: {target}")
    cms_name = enumerate_cms(target)
    if cms_name:
        display_cms_result(cms_name)
    else:
        console.print(Fore.RED + "[!] CMS could not be detected.")
    console.print(Fore.CYAN + "[*] CMS Enumeration completed.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        main(target_url)
    else:
        console.print(Fore.RED + "[!] No target URL provided.")
