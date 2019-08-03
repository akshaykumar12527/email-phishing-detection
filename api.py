from flask import Flask, escape, request
import json
import urllib.parse
from full_email_check import *
from text_analysis import *

# with open('email_json.js') as dataFile:
#     data = dataFile.read()
#     obj = data[data.find('{') : data.rfind('}')+1]
#     jsonObj = json.loads(obj)
# print(jsonObj)
# em=jsonObj['email']

app = Flask(__name__)
@app.route('/',methods=['POST'])

def return_function():
	e_mail = request.get_json()
	# e_mail = json.loads(e_mail)
	em=e_mail['your_email']

	json_status ={}
	soup = BeautifulSoup(em,'html.parser')

	def links_from_emails(soup):
		links = []
		for link in soup.find_all('a'):
			try:
				links.append(link['href'].replace('\\"',''))
			except KeyError:
				pass
		return links

	links = links_from_emails(soup)
	json_status['links_in_email']=links

	def get_hostname_from_url(url):
	    hostname = url
	    pattern = "https://|http://|www.|https://www.|http://www."
	    pre_pattern_match = re.search(pattern, hostname)

	    if pre_pattern_match:
	        hostname = hostname[pre_pattern_match.end():]
	        post_pattern_match = re.search("/", hostname)
	        if post_pattern_match:
	            hostname = hostname[:post_pattern_match.start()]
	    return hostname

	if len(links)>0:
		for url in links:
			try:
				r=requests.get(url)
				if str(r) == '<Response [200]>':
					domain = get_hostname_from_url(url)
					list={}
					list['url']=url
					list['base_domain']=domain
					dmarcrecords=dmarc_records(domain)
					list['MX_records']=MX(dmarcrecords)
					list['DMARC_records']=DMARC(dmarcrecords)
					list['google_safe_browsing']=google_api_check(domain)
					list['having_ip_address']=having_ip_address(url)
					list['url_length']=url_length(url)
					list['shortening_service']=shortening_service(url)
					list['having_at_symbol']=having_at_symbol(url)
					list['double_slash_redirecting']=double_slash_redirecting(url)
					list['prefix_suffix']=prefix_suffix(url)
					list['having_sub_domain']=having_sub_domain(url)
					list['domain_ssl_registration_length']=domain_ssl_registration_length(domain)
					list['number_of_domains']=number_of_domains(domain)
					list['http_https_token']=https_token(url)
					list['only_https_token']=only_https_token(url)
					list['abnormal_url']=abnormal_url(domain,url)
					list['age_of_domain']=age_of_domain(domain)
					list['web_traffic']=web_traffic(domain)
					list['google_index_url']=google_index(url)
					list['google_index_base_domain']=google_index(domain)
					list['statistical_report']=statistical_report(url, domain)
					list['url_same_as_string']=if_url_same_as_string(soup)
					list['request_url']=request_url(url, soup, domain)
					list['url_of_anchor']=url_of_anchor(url, soup, domain)
					list['links_in_tags']=links_in_tags(url, soup, domain)
					json_status[url]=list
				else:
					json_status[url]='url does not exist'
			except:
				pass
	else:
		json_status['links_in_email']=len(links)
		
	if soup.p!=None:
		text_features={}
		text_features['spell_check']=spell_check(soup)
		text_features['words_from_phishing_emails']=words_from_phishing_emails(soup)
		text_features['positive_sentiment_score']=positive_sentiment_score(soup)
		text_features['emotions']=emotions(soup)
		json_status['text_analysis']=text_features
	else:
		json_status['text_analysis']='no text in email'

	html_features={}
	html_features['html_formatted']=html_formatted(soup)
	html_features['if_javascript']=if_javascript(soup)
	html_features['submitting_to_email']=submitting_to_email(soup)
	html_features['i_frame']=i_frame(soup)
	json_status['html_features_of_email']=html_features
	# return soup.prettify()
	return json.dumps(json_status,indent=4,sort_keys=True)

app.run(debug=True)