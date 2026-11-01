import argparse
import logging
import requests
import sys
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


def parsed_origin(url):
    """Returns (scheme, host, effective port) for a URL, or None if unparsable."""
    try:
        parts = urlparse(url)
        if not parts.scheme or not parts.hostname:
            return None
        port = parts.port
        if port is None:
            port = 443 if parts.scheme == "https" else 80
        return (parts.scheme.lower(), parts.hostname.lower(), port)
    except ValueError:
        return None


def url_matches(candidate_url, target_url):
    """
    True when candidate_url is on the same parsed origin as target_url
    (scheme, host, and port), and, when the target names a path beyond
    the root, the candidate path starts with that path. A string prefix
    of a different origin never matches.
    """
    candidate_origin = parsed_origin(candidate_url)
    target_origin = parsed_origin(target_url)
    if candidate_origin is None or target_origin is None:
        return False
    if candidate_origin != target_origin:
        return False
    target_path = urlparse(target_url).path
    if target_path and target_path != "/":
        return urlparse(candidate_url).path.startswith(target_path)
    return True


def check_redirect(url, redirect_urls, timeout=5):
    """
    Checks whether the URL, or any hop in its redirect chain, lands on
    any of the specified redirect URLs.
    :param url: The URL to check for redirection.
    :param redirect_urls: A list of URLs to check against.
    :param timeout: Timeout for the request in seconds.
    :return: A (matches, error) pair. matches is a list of
             (target_url, hop_url) pairs, one per matched target, for
             the first hop that matched it. error is a string when the
             request itself failed, in which case no verdict was earned.
    """
    try:
        response = requests.get(url, allow_redirects=True, timeout=timeout)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during request: {e}")
        return [], str(e)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return [], str(e)

    # Every hop is evidence: each history entry's Location target, plus
    # the final URL. An error status at the end of the chain does not
    # discard the chain, so raise_for_status is never called here.
    hop_urls = []
    for past in response.history:
        location = past.headers.get("Location")
        if location:
            hop_urls.append(urljoin(past.url, location))
    hop_urls.append(response.url)

    matches = []
    matched_targets = set()
    for hop_url in hop_urls:
        for target_url in redirect_urls:
            if target_url in matched_targets:
                continue
            if url_matches(hop_url, target_url):
                matches.append((target_url, hop_url))
                matched_targets.add(target_url)
                logging.warning(f"Potential open redirect found: {url} redirects through {hop_url} matching {target_url}")

    return matches, None


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
        sys.exit(1)

    for redirect_url in redirect_urls:
        if not is_valid_url(redirect_url):
            logging.error(f"Invalid redirect URL provided: {redirect_url}")
            sys.exit(1)

    if timeout <= 0:
        logging.error("Timeout value must be greater than 0.")
        sys.exit(1)

    logging.info(f"Checking {url} for open redirect to: {redirect_urls}")

    # Check for open redirect vulnerability
    matches, error = check_redirect(url, redirect_urls, timeout)

    if error is not None:
        print(f"Check failed for URL: {url}. The target could not be reached, so no verdict was earned.")
        sys.exit(1)

    if matches:
        print(f"Potential open redirect vulnerability found for URL: {url}")
        for target_url, hop_url in matches:
            print(f"  Redirects to: {target_url} (hop: {hop_url})")
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