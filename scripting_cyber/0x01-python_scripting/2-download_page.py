#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup


def download_page(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.prettify()
    except requests.exceptions.RequestException as error:
        return str(error)
