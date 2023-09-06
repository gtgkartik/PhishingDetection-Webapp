import numpy as np
import pickle
import pandas as pd
import tldextract
import whois
import requests
import datetime
from bs4 import BeautifulSoup
import streamlit as st
import pickle
import pandas as pd
import re
from urllib.parse import urlparse
import tldextract
import requests
from bs4 import BeautifulSoup
import whois21
from datetime import datetime
from googlesearch import search
#Pre Processing


def phishingDetection(url):
    features = {}

    parsed_url = urlparse(url)
    # URL Length
    url_length = len(parsed_url.hostname)
    features['length_url'] = url_length

    # length of hostname
    length_hostname = len(url)
    features['length_hostname'] = length_hostname

    # if Ip or no ip
    # Extract hostname from URL using regex
    hostname1 = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url)
    if hostname1:
        # Extract IP address from hostname
        ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname1[0])
        if ip:
            features["ip"] = 1
        else:
            features['ip'] = 0

    # nb_dots
    nb_dots = url.count('.')
    features["nb_dots"] = nb_dots

    # nb_qm
    nb_qm = url.count('?')

    if nb_qm > 0:
        features['nb_qm'] = 1
    else:
        features['nb_qm'] = 0

        # nb_eq
    nb_eq = url.count('=')
    features['nb_eq'] = nb_eq

    # nb_slash
    nb_slash = url.count('/')
    features['nb_slash'] = nb_slash

    # nb_www
    nb_www = url.count('www')

    if nb_www == 1:
        features['nb_www'] = 1
    else:
        features['nb_www'] = 0

        # ratio_digits_url
    digits_count = len(re.findall(r'\d', url))
    non_digits_count = len(url) - digits_count
    ratio_digits = digits_count / non_digits_count
    # Add the "ratio_digits_url" feature to the dictionary
    features["ratio_digits_url"] = ratio_digits if ratio_digits > 0 else 0

    # ratio_digits_host
    hostname = parsed_url.hostname

    num_digits = sum(c.isdigit() for c in hostname)
    num_nondigits = 1

    if num_digits == 0:
        features['ratio_digits_host'] = 0
    else:
        features['ratio_digits_host'] = num_nondigits / num_digits

        # tld_in_subdomain
    subdomain, domain, suffix = tldextract.extract(url)
    subdomain_components = subdomain.split('.')
    tld = domain

    if tld in subdomain_components:
        features['tld_in_subdomain'] = 1
    else:
        features['tld_in_subdomain'] = 0

    # prefix_suffix
    if '-' in hostname:
        features['prefix_suffix'] = 1
    else:
        features['prefix_suffix'] = 0

    # shortest_word_host

    # Split the hostname into words
    words = hostname.split('.')

    # Find the shortest word
    shortest_word = min(words, key=len)

    # Calculate the ratio of the shortest word to the total length of the hostname
    ratio_shortest_word = len(shortest_word) / len(hostname)

    # Create a dictionary with the feature value
    features['shortest_word_host'] = len(shortest_word)

    # longest_words_raw
    def longest_words_raw(url):
        parsed_url = urlparse(url)
        path = parsed_url.path
        query = parsed_url.query
        if path:
            longest_path_word = max(path.split('/'), key=len)
        else:
            longest_path_word = ''
        if query:
            longest_query_word = max(query.split('&'), key=lambda x: len(x.split('=')[0]))
        else:
            longest_query_word = ''
        return max(longest_path_word, longest_query_word, key=len)

    features['longest_words_raw'] = len(longest_words_raw(url))

    # longest_word_path
    def longest_word_path(url):

        path = urlparse(url).path
        path_words = path.split('/')
        path_words = [word for word in path_words if word != '']
        if not path_words:
            return 0
        return max(len(word) for word in path_words)

    features['longest_word_path'] = longest_word_path(url)

    # nb_hyperlinks
    def calculate_nb_hyperlinks(url):
        # Make a request to the URL to get the HTML content
        response = requests.get(url)

        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extract all the hyperlinks using BeautifulSoup's find_all method
        hyperlinks = soup.find_all('a')

        # Return the number of hyperlinks found
        return len(hyperlinks)

    features['nb_hyperlinks'] = calculate_nb_hyperlinks(url)

    # ratio_intHyperlinks
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        num_total_links = len(soup.find_all("a"))
        num_internal_links = 0
        for link in soup.find_all("a"):
            if link.get("href") and url in link.get("href"):
                num_internal_links += 1
        ratio_intHyperlinks = num_internal_links / num_total_links
        features['ratio_intHyperlinks'] = ratio_intHyperlinks
    except Exception as e:
        ratio_intHyperlinks = 0
        features['ratio_intHyperlinks'] = 0

    # empty_title
    try:
        # Make request to URL and get HTML content
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Check if title tag exists and if it's empty
        title = soup.title.string.strip()
        if not title:
            features['empty_title'] = 1
        else:
            features['empty_title'] = 0

    except:
        # Set empty_title to 1 if any error occurs
        features['empty_title'] = 1

    # Domain In Title
    try:
        soup = BeautifulSoup(requests.get(url, timeout=5).content, 'html.parser')
        title = soup.title.string.strip()
        netloc = urlparse(url).netloc
        if netloc in title:
            features['domain_in_title'] = 1
        else:
            features['domain_in_title'] = 0
    except:
        features['domain_in_title'] = 0

    # domain_age
    urlwhois = domain + "." + suffix
    whois = whois21.WHOIS(urlwhois)

    # Third step is to check if the operation was successful
    if not whois.success:
        features['domain_age'] = -1
    else:
        data = whois.whois_data
        date = data['CREATION DATE']
        date_obj = datetime.strptime(date, '%Y-%m-%dT%H:%M:%SZ')
        current_date = datetime.now()
        days_diff = (current_date - date_obj).days
        features['domain_age'] = days_diff

    # google_index
    def google_index(url):
        site = search(url, 5)
        return 1 if site else 0

    features['google_index'] = google_index(url)
    features_df = pd.DataFrame([features])

    loaded_model = pickle.load(open('./model_phishing_webpage_classifer94.plk', 'rb'))
    prediction = loaded_model.predict(features_df)

    if prediction[0] == 1 :
        return "This is a phishing link"
    else :
        return "This is not a phishing link"


url = "http://shadetreetechnology.com/V4/validation/a111aedc8ae390eabcfa130e041a10a4"
print(phishingDetection(url))


def main():
    #title
    st.title("Phishing Detection Web App")

    # Getting the input data from the user
    url = st.text_input("Enter URL")
    print(type(url))
    # Prediction
    prediction = ''

    # Creating a button
    if st.button("Result"):
        prediction = phishingDetection(url)

    st.success(prediction)

if __name__ == '__main__' :
    main()