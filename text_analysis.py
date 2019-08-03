import gensim.models as gsm
import numpy as np
import math
import nltk
from spellchecker import SpellChecker
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from textblob import TextBlob
import string
from nltk import pos_tag
from scipy import spatial
from nltk.tokenize import word_tokenize, sent_tokenize
ps=PorterStemmer()
stop_words = stopwords.words('english')


from bs4 import BeautifulSoup

most_commonly_occuring_words=['click', 'pleas', 'us', 'dear', 'name', 'inform', 'thi', 'card', 'account', 'transact', 'bank', 'regard', 'activ', 'contact', 'date', 'email', 'credit', 'get', 'report', 'day', 'greet', 'may', 'visit', 'branch', 'thank', 'link', 'need', 'number', 'make', 'request', 'sincer', 'case', 'help', 'call', 'univers', 'team', 'immedi', 'touch', 'sure', 'want', 'limit', 'choos', 'work', 'home', 'kindli', 'phonebank', 'know', 'done', 'soon', 'would', 'unit', 'debit', 'verifi', 'clarif', 'locat', 'member', 'receiv', 'cityst', 'closest', 'use', 'usd', 'kind', 'commun', 'wish', 'certain', 'noxx7431', 'best', 'address', 'complet', 'also', 'record', 'colleg', 'custom', '698', 'amazoncom', '’', 'compani', 'place', 'continu', 'protect', 'secur', 'made', 'unexpect', 'deloitt', 'updat', 'depart', 'employe', 'student', 'without', 'interrupt', 'hr']

def text(soup):
	final_text = ''
	tokens = []
	for tag in soup.find_all('p'):
		text = tag.getText().translate(str.maketrans('', '', string.punctuation))
		word_tokens=text.split()
		new_new_tokens=[]
		for word in word_tokens:
			if 'http' in word:
				continue
			else:
				new_new_tokens.append(word)
				tokens.append(ps.stem(word))
		if len(word_tokens)>0:
			final_text = final_text+' '+' '.join(new_new_tokens)
	return final_text, tokens

def spell_check(soup):
	t,tok=text(soup)
	w=word_tokenize(t)
	spell = SpellChecker()
	misspelled = spell.unknown(t)
	wg_list=[]
	for word in misspelled:
		wrong_words = spell.correction(word)
		wg_list.append(wrong_words)
	# return -1 if len(wg_list)>0 else 1
	return len(wg_list)

def words_from_phishing_emails(soup):
	t, tokens = text(soup)
	count=0
	total_words = len(tokens)
	for word in tokens:
		if word in most_commonly_occuring_words:
			count+=1
	return round(count/total_words*100)

def positive_sentiment_score(soup):
	t,tok = text(soup)
	return (TextBlob(t).polarity)*100

w2v = gsm.KeyedVectors.load_word2vec_format('GoogleNews-vectors-negative300.bin.gz', binary=True, limit=50000) 
EMAIL_EMOTIONS = ['urgent', 'greed', 'panic', 'fear', 'worry']

CLONE_N = 30 
VALID_POS_LIST = ['NN', 'VB', 'JJ']

def vectorize(caption): 
    result = []
    for sent in sent_tokenize(caption):
        for word, pos in pos_tag(word_tokenize(sent)):
            s = word.translate(string.punctuation)
            for valid_pos in VALID_POS_LIST:
                if valid_pos in pos:
                    if s not in stop_words: 
                        try: 
                            vec = np.zeros_like(w2v['hello'])
                            result.append(np.add(vec, w2v[s])) 
                        except: 
                            pass
                    break
    return result

def distance_transformer(captions, emotions_list):
    result = []
    for caption in captions:
        average_vec = np.mean(vectorize(caption), axis=0)
        to_append = []
        for emotion in emotions_list: 
            if emotions_list == EMAIL_EMOTIONS:
                dist = spatial.distance.cosine(average_vec, w2v[emotion]) 
#                 print(1-dist,emotion)
            if math.isnan(dist):
                to_append.append([emotion,0.0*100])
            else: 
                to_append.append([emotion,(1-dist)*100])
        result.append(to_append)
    return to_append

def emotions(soup):
	t,tok = text(soup)
	return distance_transformer([t], EMAIL_EMOTIONS)
