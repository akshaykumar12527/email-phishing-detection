from bs4 import BeautifulSoup
import urllib
import bs4
import re
import socket
import whois
from datetime import datetime, timezone
import time
from googlesearch import search
from patterns import *
import sys
import subprocess
import requests
import json
from nltk.tokenize import word_tokenize
from spellchecker import SpellChecker

def dmarc_records(domain):
    command='checkdmarc',domain
    strg = str(command)
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    result = p.communicate()[0].decode().replace('\n','')
    return json.loads(result)

def MX(dmarcrecords):
    if ('error' in dmarcrecords['mx']):
        return -1
    if ('warnings' in dmarcrecords['mx']):
        return -1
    else:
        return 1

def DMARC(dmarcrecords):
    if 'error' in dmarcrecords['dmarc']:
        return -1
    else:
        return 1

# def ip_blacklist_check_function(domain):
#     number = blacklist_check(domain)
#     return number

def google_api_check(doamin):
    URL='https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyDU3yw7ZLIo2zls4uhq6Q5pmU-hfnJACEY'

    PARAMS=json.dumps({"client": {
        "clientId":      "283441782188-u4tsi7brvkhcmkvpm7kja81fgkl7s2gp.apps.googleusercontent.com",
        "clientVersion": "1.5.2"
      },
    "threatInfo": {
          "threatTypes":      ["SOCIAL_ENGINEERING"],
          "platformTypes":    ["WINDOWS"],
          "threatEntryTypes": ["URL"],
          "threatEntries": [
            {"url": "http://www.pbmails.payback.in/"}]}})

    headers = {
        'Content-Type': "application/json",
        'User-Agent': "PostmanRuntime/7.15.0",
        'Accept': "*/*",
        'Cache-Control': "no-cache",
        'Postman-Token': "462e22a1-2114-4dec-b36b-f3537fb4a08e,0d5ef817-dfdb-4f0c-a9ba-ba909beafa19",
        'Host': "safebrowsing.googleapis.com",
        'accept-encoding': "gzip, deflate",
        'content-length': "354",
        'Connection': "keep-alive",
        'cache-control': "no-cache",
        'Referer': "https://www.google.com"
        }
    response = requests.request("POST", URL, data=PARAMS, headers=headers)
    return -1 if len(response.text)>3 else 1

def having_ip_address(url):
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    match = re.search(ip_address_pattern, url)
    return -1 if match else 1

# def parse_url(url):
#     return url[url.find('//')+2:url.find('/',url.find('//')+3)]

def url_length(url):
    if len(url) < 54:
        return 1
    if 54 <= len(url) <= 75:
        return 0
    return -1

def shortening_service(url):
    match = re.search(shortening_services, url)
    return -1 if match else 1

def having_at_symbol(url):
    match = re.search('@', url)
    return -1 if match else 1


def double_slash_redirecting(url):
    last_double_slash = url.rfind('//')
    return -1 if last_double_slash > 6 else 1


def prefix_suffix(domain):
    match = re.search('-', domain)
    return -1 if match else 1

def having_sub_domain(url):
    if having_ip_address(url) == -1:
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        pos = match.end()
        url = url[pos:]
    num_dots = [x.start() for x in re.finditer(r'\.', url)]
    if len(num_dots) <= 3:
        return 1
    elif len(num_dots) == 4:
        return 0
    else:
        return -1

# def domain_registration_length(domain):
#     try:    
#         w = whois.query(domain)
#         if w.expiration_date!=None:
#             expiration_date = w.expiration_date.date()
#             now = datetime.now(timezone.utc).date()
#             registration_length = 0
#             if expiration_date:
#                 registration_length = abs((expiration_date - now).days)
#             return -1 if registration_length / 365 <= 1 else 1
#         return -1
#     except Exception as e:
#         return -1

def domain_ssl_registration_length(domain):
    output = subprocess.run(['sslcheck',domain],stdout=subprocess.PIPE).stdout.decode()
    result = output.find('Certificate chain is ok')
    if result!=-1:
        time=int(output[output.find('(')+3:output.find('days')].strip())
        return -1 if time <= 90 else 1
    else:
        return -1

def number_of_domains(url):
    try:
        r = requests.get(url)
        end_domain = r.url
        return 1 if get_hostname_from_url(url) == get_hostname_from_url(end_domain) else -1
    except:
        return 1

def html_formatted(soup):
    links =soup.find_all(['html','body','meta','head'])
    return -1 if links==None else 1

def if_javascript(soup):
    find = soup.find('script')
    return -1 if find else 1

def https_token(url):
    match = re.search(http_https, url)
    if match and match.start() == 0:
        url = url[match.end():]
    match = re.search('http|https', url)
    return -1 if match else 1

def only_https_token(url):
    if url.find('https')==-1:
        return -1
    return 1

def submitting_to_email(soup):
    for form in soup.find_all('form', action=True):
        return -1 if "mailto:" in form['action'] else 1
    return 1

def abnormal_url(domain, url):
    try:
        w = whois.query(domain)
        hostname = w.name
        match = re.search(hostname, url)
        return 1 if match else -1
    except Exception as e:
        return -1

def i_frame(soup):
    for i_frame in soup.find_all('i_frame', width=True, height=True, frameBorder=True):
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['frameBorder'] == "0":
            return -1
        if i_frame['width'] == "0" or i_frame['height'] == "0" or i_frame['frameBorder'] == "0":
            return 0
    return 1

def age_of_domain(domain):
    try:
        w = whois.query(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        ageofdomain = 0
        if expiration_date:
            ageofdomain = abs((expiration_date - creation_date).days)
        return -1 if ageofdomain / 30 < 6 else 1
    except Exception as e:
        return -1

def web_traffic(url):
    try:
        rank = \
            bs4.BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
                "REACH")['RANK']
    except TypeError:
        return -1
    rank = int(rank)
    return 1 if rank < 100000 else 0


def google_index(url):
    site = search(url, 5)
    return 1 if site else -1


def statistical_report(url, hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
    except:
        return -1
    url_match = re.search(
        r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    ip_match = re.search(
        '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
        '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
        '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
        '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
        '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
        '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
        ip_address)
    if url_match:
        return -1
    elif ip_match:
        return -1
    else:
        return 1

def request_url(wiki, soup, domain):
    i = 0
    success = 0
    pattern = "https://|http://|www.|https://www.|http://www."
    for img in soup.find_all('img', src=True):
        dots = [x.start() for x in re.finditer(r'\.', img['src']) if re.search(pattern, img['src'])]
        if wiki in img['src'] or domain in img['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for audio in soup.find_all('audio', src=True):
        dots = [x.start() for x in re.finditer(r'\.', audio['src']) if re.search(pattern, audio['src'])]
        if wiki in audio['src'] or domain in audio['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for embed in soup.find_all('embed', src=True):
        dots = [x.start() for x in re.finditer(r'\.', embed['src']) if re.search(pattern, embed['src'])]
        if wiki in embed['src'] or domain in embed['src'] or len(dots) == 1:
            success = success + 1
        i = i + 12

    for i_frame in soup.find_all('i_frame', src=True):
        dots = [x.start() for x in re.finditer(r'\.', i_frame['src']) if re.search(pattern, i_frame['src'])]
        if wiki in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    try:
        percentage = success / float(i) * 100
    except:
        return 1

    if percentage < 22.0:
        return 1
    elif 22.0 <= percentage < 61.0:
        return 0
    else:
        return -1

def url_of_anchor(wiki, soup, domain):
    i = 0
    unsafe = 0
    for a in soup.find_all('a', href=True):
        if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                wiki in a['href'] or domain in a['href']):
            unsafe = unsafe + 1
        i = i + 1
        # print a['href']
    try:
        percentage = unsafe / float(i) * 100
    except:
        return 1
    if percentage < 31.0:
        return 1
        # return percentage
    elif 31.0 <= percentage < 67.0:
        return 0
    else:
        return -1

def links_in_tags(wiki, soup, domain):
    i = 0
    success = 0
    pattern = "https://|http://|www.|https://www.|http://www."
    for link in soup.find_all('link', href=True):
        dots = [x.start() for x in re.finditer(r'\.', link['href']) if re.search(pattern, link['href'])]
        if wiki in link['href'] or domain in link['href'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for script in soup.find_all('script', src=True):
        dots = [x.start() for x in re.finditer(r'\.', script['src']) if re.search(pattern, script['src'])]
        if wiki in script['src'] or domain in script['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1
    try:
        percentage = success / float(i) * 100
    except:
        return 1

    if percentage < 17.0:
        return 1
    elif 17.0 <= percentage < 81.0:
        return 0
    else:
        return -1

def sfh(wiki, soup, domain):
    for form in soup.find_all('form', action=True):
        if form['action'] == "" or form['action'] == "about:blank":
            return -1
        elif wiki not in form['action'] and domain not in form['action']:
            return 0
        else:
            return 1
    return 1

def if_url_same_as_string(soup):
    n=0
    tagss=[tag for tag in soup.find_all('a') if tag.string!=None]
    for tag in tagss:
        if 'http' in tag.string:
            if tag.string != tag.a: n-=1
            else: n+=1
    return n





