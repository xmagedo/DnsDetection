import ngram
import operator
import collections
import pickle as pkl
import numpy
import tldextract
import langid
import pygeoip
import sys
import math
import operator
import io


class DNSchDetector():

    def __init__(self, infile):
        self.domain_ip_d = collections.defaultdict(str)
        self.infile = infile
        self.gi = pygeoip.GeoIP('GeoIP.dat')
        self.chinese_punycode_doms = set()
        self.score_threshold = 0.5
        self.domain_dict = collections.defaultdict(list)
        self.whitelist = self.make_whitelist()
        self.unigram_corpus = collections.Counter()
        self.bigram_corpus = collections.Counter()
        self.trigram_corpus = collections.Counter()
        self.quadgram_corpus = collections.Counter()
        self.cor_uni_sum = 0
        self.cor_bi_sum = 0
        self.cor_tri_sum = 0
        self.cor_quad_sum = 0

    # Check whitelist file
    

    def make_whitelist(self):
        whitelist = set()
        for domain in open(
            b"/Users/abdulmajeedalroumi/Desktop/DNS_detection/whitelist.txt",
                "r"):
            domain = domain.strip()
            whitelist.add(domain)
        return whitelist

    # if domain has any of the whitelisted words

    def whitelisted(self, domain):
        whitelisted = False
        for word in self.whitelist:
            if word in domain:
                whitelisted = True
        return whitelisted

       # if i not digits in domain#

    def clean(self, domain):

        domain = ''.join([i for i in domain if not i.isdigit()])
        domain = domain.replace(".", "")
        domain = domain.replace("-", "")
        return domain

    # Reading pickle files for serializing and de-serializing

    def read_corpus_file(self):
        uni, bi, tri, quad = pkl.load(
            open(
                "/Users/abdulmajeedalroumi/Desktop/DNS_detection/CHDictionaryCorpus.p", "rb"))
        with open("/Users/abdulmajeedalroumi/Desktop/DNS_detection/CHDomainCorpus.p", "rb") as f:
            u, b, t, q = pkl.load(f, encoding="latin1")
        uni += u
        bi += b
        tri += t
        quad += q

        return uni, bi, tri, quad

    # Implementing nGrams
    def getNGrams(self, domain):

        uni_index = ngram.NGram(N=1)
        bi_index = ngram.NGram(N=2)
        tri_index = ngram.NGram(N=3)
        quad_index = ngram.NGram(N=4)

        unigrams = list(uni_index.ngrams(domain))
        bigrams = list(bi_index.ngrams(domain))
        trigrams = list(tri_index.ngrams(domain))
        quadgrams = list(quad_index.ngrams(domain))

        return unigrams, bigrams, trigrams, quadgrams

    def filter_language(self, domain):

        filter_lang_set = set(["en", "es"])

        if langid.classify(domain)[0] in filter_lang_set:
            return True
        return False
    
    def analyze_domain(self, domain, num_subdomains):  
        entropy = self.calculate_entropy(domain)
        domain_length = len(domain)
        # num_subdomains = domain.count('.')  
        hex_chars = sum(domain.count(char) for char in '0123456789abcdef')
        hex_ratio = hex_chars / len(domain)
        unigrams, bigrams, trigrams, quadgrams = self.getNGrams(domain)
        num_unigrams = len(unigrams)
        num_bigrams = len(bigrams)
        print(f'Domain: {domain}')
        print(f'Entropy: {entropy}')
        print(f'Domain Length: {domain_length}')
        print(f'Number of Subdomains: {num_subdomains}')
        print(f'Hex Ratio: {hex_ratio}')
        print(f'Number of Unigrams: {num_unigrams}')
        print(f'Number of Bigrams: {num_bigrams}')




    def calculate_entropy(self, domain):
        char_counts = collections.Counter(domain)
        char_frequencies = [count / len(domain) for count in char_counts.values()]
        entropy = -sum(f * math.log2(f) for f in char_frequencies)
        return entropy

        # ... rest of your code above

    def read_clean_data(self):

        unigram_set = collections.Counter()
        bigram_set = collections.Counter()
        trigram_set = collections.Counter()
        quadgram_set = collections.Counter()

        with open(self.infile, "r") as file:
            for line in file:

                line = line.strip()
                if ',' not in line:
                    continue
                domain, ip = line.split(",")
                self.domain_ip_d[domain] = ip

                if self.filter_language(domain):
                    continue

                FQDN = domain

                ext = ""
                try:
                    ext = tldextract.extract(domain)
                except BaseException:
                    ext = ""

                if self.whitelisted(domain):
                    continue
                
                num_subdomains = domain.count('.') - 1  # Corrected indentation here
                # most chinese domains have these Top level domains, wouldn't have
                # .eu or .ru
                whiteTLDs = set(["com",
                                 "cn",
                                 "tw",
                                 "hk",
                                 "net",
                                 "info",
                                 "biz",
                                 "cc",
                                 "so",
                                 "com.cn",
                                 "org.cn",
                                 "org",
                                 "in",
                                 "com.tw",
                                 "net.cn"])

                if ext.suffix not in whiteTLDs:
                    continue
				
                domain = f"{ext.domain}.{ext.suffix}"
                domain = self.clean(domain)
                self.analyze_domain(domain, num_subdomains)
                # self.analyze_domain(domain)
                unigrams, bigrams, trigrams, quadgrams = self.getNGrams(domain)

                unigram_c = collections.Counter(unigrams)
                bigram_c = collections.Counter(bigrams)
                trigram_c = collections.Counter(trigrams)
                quadgram_c = collections.Counter(quadgrams)

                self.domain_dict[FQDN].append(unigram_c)
                self.domain_dict[FQDN].append(bigram_c)
                self.domain_dict[FQDN].append(trigram_c)
                self.domain_dict[FQDN].append(quadgram_c)






    # Create sum of all corpus totals

    def sum_cor(self, c):
        c = dict(c)
        total = 0
        for k, v in c.items():
            total += v
        return total

    # Calculate bigram probability
    def get_bigram_probability(self, bigram):
        return float(self.bigram_corpus[bigram]) / \
            float(self.uni_corpus[bigram[0:1]])

    # Calculate trigram probability
    def get_tri_probability(self, trigram):
        return float(self.trigram_corpus[trigram]) / \
            float(self.bigram_corpus[trigram[0:2]])

    # Calculate quadgram probability
    def get_quad_probability(self, quadgram):
        return float(self.quadgram_corpus[quadgram]) / \
            float(self.trigram_corpus[quadgram[0:3]])

    def create_probability_vectors(self):

        bigram_result = {}
        trigram_result = {}
        quadgram_result = {}

        total_d = collections.defaultdict(float)

        for domain, grams in self.domain_dict.items():

            bi_val = 1.0
            tri_val = 1.0
            quad_val = 1.0

            bi = dict(grams[1])
            tri = dict(grams[2])
            quad = dict(grams[3])

            bigram_probability = 0.0
            trigram_probability = 0.0
            quadgram_probability = 0.0

            for bigram, freq in bi.items():

                try:
                    bigram_probability = self.get_bigram_probability(bigram)
                except BaseException:
                    continue

                if bigram_probability == 0.0:
                    bigram_probability = 1.0 / self.cor_bi_sum

                bigram_probability = bigram_probability**freq

            for trigram, freq in tri.items():
                try:
                    trigram_probability = self.get_tri_probability(trigram)
                except BaseException:
                    continue

                if trigram_probability == 0.0:
                    trigram_probability = 1.0 / self.cor_tri_sum
                trigram_probability = trigram_probability**freq

            for quadgram, freq in quad.items():
                try:
                    quadgram_probability = self.get_quad_probability(quadgram)
                except BaseException:
                    continue

                if quadgram_probability == 0.0:
                    quadgram_probability = 1.0 / self.cor_quad_sum

                quadgram_probability = quadgram_probability**freq

            bi_val *= bigram_probability
            tri_val *= trigram_probability
            quad_val *= quadgram_probability

            total_domain_score = (
                (1.0 * float(bi_val)) + (2.0 * float(tri_val)) + (3.0 * float(quad_val))) / 6.0
            total_d[domain] = total_domain_score
        return dict(total_d)

    def getCC(self, ip):
        country_code = ""
        try:
            country_code = self.gi.country_code_by_addr(ip)
        except BaseException:
            country_code = ""
        return country_code

    def getCC_weight(self, cc):
        cc_weight = 0.0
        if cc == 'CN' or cc == 'HK' or cc == 'TW':
            cc_weight = 0.5
        return cc_weight

    def get_lang_weight(self, domain):
        lang_weight = 0.0
        if langid.classify(domain)[0] == "zh":
            lang_weight = 0.5
        return lang_weight

    def get_punycode_weight(self, domain):
        punycode_weight = 0.0
        if "xn--" in domain:
            punycode_weight = 0.5
        return punycode_weight

    # Words unique to mandarin
    def check_giveaway_words(self, domain):
        g_score = 0.0
        giveaways = set(["zhan",
                         "zhuo",
                         "zhen",
                         "zhuan",
                         "zhon",
                         "chang",
                         "chuan",
                         "cheng",
                         "xiang",
                         "qian",
                         "xiong",
                         "xian",
                         "xuan",
                         "jiang",
                         "chuang",
                         "ijin"])
        for g in giveaways:
            if g in domain:
                g_score += .5
        return g_score


if __name__ == "__main__":

    pd = DNSchDetector(sys.argv[1])
    uni_corpus, bi_corpus, tri_corpus, quad_corpus = pd.read_corpus_file()
    pd.unigram_corpus = uni_corpus
    pd.bigram_corpus = bi_corpus
    pd.trigram_corpus = tri_corpus
    pd.quad_corpus = quad_corpus
    pd.read_clean_data()
    pd.cor_uni_sum = pd.sum_cor(uni_corpus)
    pd.cor_bi_sum = pd.sum_cor(bi_corpus)
    pd.cor_tri_sum = pd.sum_cor(tri_corpus)
    pd.cor_quad_sum = pd.sum_cor(quad_corpus)

    total_d = pd.create_probability_vectors()
    scoring_vector = []
    total_probability = 0.0

    for domain, prob in total_d.items():

        total_domain_score = 0
        ip = pd.domain_ip_d[domain]
        cc = pd.getCC(ip)
        cc_weight = pd.getCC_weight(cc)
        lang_weight = pd.get_lang_weight(domain)
        punycode_weight = pd.get_punycode_weight(domain)
        giveaway_weight = pd.check_giveaway_words(domain)
        total_domain_score = prob + lang_weight + \
            cc_weight + punycode_weight + giveaway_weight
        scoring_vector.append((domain, total_domain_score))
        total_probability += total_domain_score

    scoring_vector = sorted(
        scoring_vector,
        key=operator.itemgetter(1),
        reverse=True)

    f = open(
        '/Users/abdulmajeedalroumi/Desktop/DNS_detection/DNSDetection/file.txt',
        'w+')
    normalized_score = 0
    count = 0
    print('Domain', 'Score')
    f.write("Domain, Score" + "\n")
    for item in scoring_vector:
        domain = item[0]
        score = item[1]
        if score < pd.score_threshold:
            continue
        normalized_score = score / total_probability
        print(domain, normalized_score)
        f.write(str(domain) + ", " + str(normalized_score) + "\n")
        count += 1
