#!/usr/bin/env python3
"""Web crawler."""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl_website(start_url, max_depth=2):
    """Crawl a website."""
    visited = set()
    domain = urlparse(start_url).netloc

    def crawl(url, depth):
        if depth > max_depth or url in visited:
            return

        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except requests.RequestException:
            return

        visited.add(url)
        print(f"Crawling: {url}")

        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a", href=True):
            url = urljoin(start_url, link["href"])

            if urlparse(url).netloc == domain:
                crawl(url, depth + 1)

    crawl(start_url, 0)
    return visited


if __name__ == "__main__":
    pass
