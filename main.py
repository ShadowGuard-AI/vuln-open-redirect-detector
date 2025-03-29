import argparse
import logging
import requests
from urllib.parse import urlparse, urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_valid_url(url):
    """
    Validates if a URL is properly formatted.
    :param url: The URL string to validate.
    :return: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def check_redirect(url, redirect_urls, timeout=5):
    """
    Checks if the given URL redirects to any of the specified redirect URLs.
    :param url: The URL to check for redirection.
    :param redirect_urls: A list of URLs to check if the URL redirects to.
    :param timeout: Timeout for the request in seconds.
    :return: A list of redirect URLs that the given URL redirects to.
    """
    try:
        response = requests.get(url, allow_redirects=True, timeout=timeout)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        redirected_url = response.url
        matches = []

        for target_url in redirect_urls:
            if redirected_url.startswith(target_url):
                matches.append(target_url)
                logging.warning(f"Potential open redirect found: {url} redirects to {target_url}")

        return matches

    except requests.exceptions.RequestException as e:
        logging.error(f"Error during request: {e}")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return []


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    :return: An argparse.ArgumentParser object.
    """
    parser = argparse.ArgumentParser(description="Detects open redirect vulnerabilities.")
    parser.add_argument("url", help="The URL to check for open redirect.")
    parser.add_argument("redirect_urls", nargs="+",
                        help="A list of redirect URLs to check against. Example: 'http://evil.com' 'http://another.evil.com'")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    return parser


def main():
    """
    The main function of the vuln-Open-Redirect-Detector tool.
    Parses command-line arguments, validates inputs, and checks for open redirect vulnerabilities.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    url = args.url
    redirect_urls = args.redirect_urls
    timeout = args.timeout

    # Input validation
    if not is_valid_url(url):
        logging.error("Invalid URL provided.")
        return

    for redirect_url in redirect_urls:
        if not is_valid_url(redirect_url):
            logging.error(f"Invalid redirect URL provided: {redirect_url}")
            return

    if timeout <= 0:
        logging.error("Timeout value must be greater than 0.")
        return

    logging.info(f"Checking {url} for open redirect to: {redirect_urls}")

    # Check for open redirect vulnerability
    matches = check_redirect(url, redirect_urls, timeout)

    if matches:
        print(f"Potential open redirect vulnerability found for URL: {url}")
        for match in matches:
            print(f"  Redirects to: {match}")
    else:
        print(f"No open redirect vulnerability found for URL: {url}")


if __name__ == "__main__":
    main()


"""
Usage examples:

1. Basic usage:
   python main.py "http://example.com/redirect?url=..." "http://evil.com"

2. Checking against multiple redirect URLs:
   python main.py "http://example.com/redirect?url=..." "http://evil.com" "http://another.evil.com"

3. Specifying a timeout:
   python main.py "http://example.com/redirect?url=..." "http://evil.com" -t 10

 Offensive tool steps:
  - Fuzzing payloads can be used in the redirect_urls to automate the process and discover potential vulnerabilities.
  - The identified open redirects can be chained with other vulnerabilities to perform more complex attacks like Cross-Site Scripting (XSS) or Server-Side Request Forgery (SSRF).

"""