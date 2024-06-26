#!/usr/bin/env python"
# coding: utf-8

import requests, argparse, sys, re
from requests.packages import urllib3
from urllib.parse import urlparse
from bs4 import BeautifulSoup


leak_infos = [] #存储元组，每个元素对应为：敏感信息正则名称、敏感信息值、敏感信息来源页面
leak_infos_match = []
leak_info_patterns = {
                      'IDCard': '[^0-9]((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))[^0-9]',
                      'phone': '[^0-9A-Za-z](1(3([0-35-9]\d|4[1-8])|4[14-9]\d|5([\d]\d|7[1-79])|66\d|7[2-35-8]\d|8\d{2}|9[89]\d)\d{7})[^0-9A-Za-z]',
                      'SpringBoot': r'((local.server.port)|(:{\"mappings\":{\")|({\"_links\":{\"self\":))',
                      'swagger': r'((swagger-ui.html)|(\"swagger\":)|(Swagger UI)|(swaggerUi))',
                      'druid': r'((Druid Stat Index)|(druid monitor))',
                      'mail': r'(([a-zA-Z0-9][_|\.])*[a-zA-Z0-9]+@([a-zA-Z0-9][-|_|\.])*[a-zA-Z0-9]+\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,}))',
                      'url': r'(=(https?://.*|https?%3(a|A)%2(f|F)%2(f|F).*))',
                      'password': r"((|'|\")([p](ass|wd|asswd|assword))(|'|\")(:|=)( |)('|\")(.*?)('|\")(|,))",
                      'oss': r"([A|a]ccess[K|k]ey[I|i][d|D]|[A|a]ccess[K|k]ey[S|s]ecret)",
                      "jdbc-connect": r"(jdbc:[a-z:]+://[A-Za-z0-9\.\-_:;=/@?,&]+)",
                      "Internal IP": r"([^0-9]((127\.0\.0\.1)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})))",
                      "Username Field": r"((|'|\")([u](ser|name|ame|sername))(|'|\")(:|=)( |)('|\")(.*?)('|\")(|,))",
                      "WeCom Key": r"([c|C]or[p|P]id|[c|C]orp[s|S]ecret)",
                      "Zoho Webhook": r"(https://creator\.zoho\.com/api/[a-z0-9/_.-]+\?authtoken=[a-z0-9]+)",
                      "Microsoft Teams Webhook": r"(https://outlook\.office\.com/webhook/[a-z0-9@-]+/IncomingWebhook/[a-z0-9-]+/[a-z0-9-]+)",
                      "Github Access Token": r"([a-z0-9_-]*:[a-z0-9_\-]+@github\.com*)",
                      "Authorization Header": r"((basic [a-z0-9=:_\+\/-]{5,100})|(bearer [a-z0-9_.=:_\+\/-]{5,100}))",
                      "key": r"(session_key|sessionKey|secret|access_token)",
                      "Bucket": r"(InvalidBucketName|NoSuchBucket|<Key>)"
                     }
#匹配敏感信息
def find_leak_info(url, text):
    for k in leak_info_patterns.keys():
        pattern = leak_info_patterns[k]
        try:
            matchs = re.findall(pattern, text, re.IGNORECASE)
            for match in matchs:
                #match_tuple = (k, match, url)
                match_tuple = (k, url)
                #match_tuple_print = (k, match, url)
                # 控制台输出和保存时判断是否重复
                if match not in leak_infos_match and match_tuple not in leak_infos:
                    leak_infos.append(match_tuple)
                    leak_infos_match.append(match)
                    print('[+]Find a leak info ==> {}'.format(match_tuple))
        except Exception as e:
            return None
#key是匹配到的正则名称,pattern是对应的正则表达式,text是url响应结果,url是jsfinder爬到的路径信息

            
def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -u http://www.xxxxxx.com")
    parser.add_argument("-u", "--url", help="The website")
    parser.add_argument("-c", "--cookie", help="The website cookie")
    parser.add_argument("-f", "--file", help="The file contains url or js")
    parser.add_argument("-ou", "--outputurl", help="Output file name. ")
    parser.add_argument("-ol", "--outputleakinfo", help="Output leak info ")
    parser.add_argument("-os", "--outputsubdomain", help="Output file name. ")
    parser.add_argument("-j", "--js", help="Find in js file", action="store_true")
    parser.add_argument("-d", "--deep",help="Deep find", action="store_true")
    return parser.parse_args()

# Regular expression comes from https://github.com/GerbenJavado/LinkFinder
def extract_URL(JS):
	pattern_raw = r"""
	  (?:"|')                               # Start newline delimiter
	  (
	    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
	    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
	    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
	    |
	    ((?:/|\.\./|\./)                    # Start with /,../,./
	    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
	    [^"'><,;|()]{1,})                   # Rest of the characters can't be
	    |
	    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
	    [a-zA-Z0-9_\-/]{1,}                 # Resource name
	    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
	    (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
	    |
	    ([a-zA-Z0-9_\-]{1,}                 # filename
	    \.(?:php|asp|aspx|jsp|json|
	         action|html|js|txt|xml)             # . + extension
	    (?:\?[^"|']{0,}|))                  # ? mark with parameters
	  )
	  (?:"|')                               # End newline delimiter
	"""
	pattern = re.compile(pattern_raw, re.VERBOSE)
	result = re.finditer(pattern, str(JS))
	if result == None:
		return None
	js_url = []
	return [match.group().strip('"').strip("'") for match in result
		if match.group() not in js_url]

# Get the page source
def Extract_html(URL):
	header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36",
	"Cookie": args.cookie}
	try:
		raw = requests.get(URL, headers = header, timeout=5, verify=False)
		if raw.status_code == 200:
			raw = raw.content.decode("utf-8", "ignore")
			return raw
		else:
			return None
	except:
		return None

# Post the page source
def Extract_html_post(URL):
	header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36",
	"Cookie": args.cookie,
	"Content-Type": "application/json"}
	data = "{}"
	try:
		raw = requests.post(URL, data=data, headers = header, timeout=5, verify=False)
		if raw.status_code == 200:
			raw = raw.content.decode("utf-8", "ignore")
			return raw
		else:
			return None
	except:
		return None

# Handling relative URLs
def process_url(URL, re_URL):
	black_url = ["javascript:"]	# Add some keyword for filter url.
	URL_raw = urlparse(URL)
	ab_URL = URL_raw.netloc
	host_URL = URL_raw.scheme
	if re_URL[0:2] == "//":
		result = host_URL  + ":" + re_URL
	elif re_URL[0:4] == "http":
		result = re_URL
	elif re_URL[0:2] != "//" and re_URL not in black_url:
		if re_URL[0:1] == "/":
			result = host_URL + "://" + ab_URL + re_URL
		else:
			if re_URL[0:1] == ".":
				if re_URL[0:2] == "..":
					result = host_URL + "://" + ab_URL + re_URL[2:]
				else:
					result = host_URL + "://" + ab_URL + re_URL[1:]
			else:
				result = host_URL + "://" + ab_URL + "/" + re_URL
	else:
		result = URL
	return result

def find_last(string,str):
	positions = []
	last_position=-1
	while True:
		position = string.find(str,last_position+1)
		if position == -1:break
		last_position = position
		positions.append(position)
	return positions

def find_by_url(url, js = False):
	if js == False:
		try:
			print("url:" + url)
		except:
			print("Please specify a URL like https://www.xxxxxx.com")
		print('--------------------------------------------获取接口信息中，请稍等--------------------------------------------')
		html_raw = Extract_html(url)
		if html_raw == None: 
			print("Fail to access " + url)
			return None
		#print(html_raw)
		html = BeautifulSoup(html_raw, "html.parser")
		html_scripts = html.findAll("script")

		script_array = {}
		script_temp = ""
		for html_script in html_scripts:
			script_src = html_script.get("src")
			if script_src == None:
				script_temp += html_script.get_text() + "\n"
			else:
				purl = process_url(url, script_src)
				script_array[purl] = Extract_html(purl)
		# 常见目录扫描
		if url[-1] != '/':
			url = url + '/'
		api_paths = r"""
		api-docs
		api/api-docs
		doc.html
		api.html
		api/v2/api-docs
		v2/api-docs
		upload
		"""
		api_path = api_paths.strip().splitlines()
        #根目录下拼接api_paths并进行接口地址提取
		for path in api_path:
			vul = url + path.strip()
			script_array[vul] = Extract_html(vul)

		script_array[url] = script_temp
		#script_array.append(script_temp)
		vul_path = r"""
		env
		actuator
		actuator/env
		api/actuator/env
		api/env
		manage/env
		management/env
		druid/login.html
		api/druid/login.html
		actuator;/env;.css
		api/actuator;/env;.css
		api;/env;.css
		;/env;.css
		"""
		paths = vul_path.strip().splitlines()
		allurls = []
        #根目录下拼接vul_path
		for path in paths:
			if path.strip() not in allurls:
				allurls.append(url + path.strip())
			else:
				continue

        #遍历js文件，获取js文件中接口信息
		for script in script_array:
			temp_urls = extract_URL(script_array[script])
			#print(len(temp_urls))
			if len(temp_urls) == 0: continue
			for temp_url in temp_urls:
				#print(temp_url)
				url_vul = process_url(script, temp_url)
				#print(url_vul)
				temp1 = urlparse(url)
				if temp1.netloc in url_vul:
					temp2 = urlparse(url_vul)
                # 获取到的接口信息中去除jpg、png、css、vue等
					if '.exe' not in temp2.path and '.png' not in temp2.path and '.jpg' not in temp2.path and '.vue' not in temp2.path and '.css' not in temp2.path and '@' not in temp2.path and '.svg' not in temp2.path:
						allurls.append(url_vul)
					if temp1.netloc == temp2.netloc and '.' not in temp2.path and ':' not in temp2.path and '{' not in temp2.path and '[' not in temp2.path:
						if url_vul[-1] == '/':
							for path in paths:
								#print(url_vul + path.strip())
								allurls.append(url_vul + path.strip())
						if '?' not in url_vul and url_vul[-1] != '/':
							for path in paths:
								#print(url_vul + '/' + path.strip())
								allurls.append(url_vul + '/' + path.strip())
		result = []
		print("获取接口数量:" + str(len(allurls)))
		print('--------------------------------------------接口获取完毕，正则匹配中------------------------------------')
		for singerurl in allurls:
			#print(singerurl)
			url_raw = urlparse(url)
			domain = url_raw.netloc
			positions = find_last(domain, ".")
			miandomain = domain
			if len(positions) > 1:miandomain = domain[positions[-2] + 1:]
			#print(miandomain)
			suburl = urlparse(singerurl)
			subdomain = suburl.netloc

			if miandomain in subdomain or subdomain.strip() == "":
				if singerurl.strip() not in result:
					result.append(singerurl)
					#匹配敏感信息
					#print(singerurl)
					resp = Extract_html(singerurl)
					resp_post = Extract_html_post(singerurl)
					find_leak_info(singerurl, resp)
					find_leak_info(singerurl, resp_post)
					#find_vul_dir(singerurl)
		print('--------------------------------------------正则匹配已结束，请查收--------------------------------------------')
		return result
	return sorted(set(extract_URL(Extract_html(url)))) or None


def find_subdomain(urls, mainurl):
	url_raw = urlparse(mainurl)
	domain = url_raw.netloc
	miandomain = domain
	positions = find_last(domain, ".")
	if len(positions) > 1:miandomain = domain[positions[-2] + 1:]
	subdomains = []
	for url in urls:
		suburl = urlparse(url)
		subdomain = suburl.netloc
		#print(subdomain)
		if subdomain.strip() == "": continue
		if miandomain in subdomain:
			if subdomain not in subdomains:
				subdomains.append(subdomain)
	return subdomains

def find_by_url_deep(url):
	html_raw = Extract_html(url)
	if html_raw == None: 
		print("Fail to access " + url)
		return None
	html = BeautifulSoup(html_raw, "html.parser")
	html_as = html.findAll("a")
	links = []
	for html_a in html_as:
		src = html_a.get("href")
		if src == "" or src == None: continue
		link = process_url(url, src)
		if link not in links:
			links.append(link)
	if links == []: return None
	print("ALL Find " + str(len(links)) + " links")
	urls = []
	i = len(links)
	for link in links:
		temp_urls = find_by_url(link)
		if temp_urls == None: continue
		print("Remaining " + str(i) + " | Find " + str(len(temp_urls)) + " URL in " + link)
		for temp_url in temp_urls:
			if temp_url not in urls:
				urls.append(temp_url)
		i -= 1
	return urls

	
def find_by_file(file_path, js=False):
	with open(file_path, "r") as fobject:
		links = fobject.read().split("\n")
	if links == []: return None
	print("ALL Find " + str(len(links)) + " links")
	urls = []
	i = len(links)
	for link in links:
		if js == False:
			temp_urls = find_by_url(link)
		else:
			temp_urls = find_by_url(link, js=True)
		if temp_urls == None: continue
		print(str(i) + " Find " + str(len(temp_urls)) + " URL in " + link)
		for temp_url in temp_urls:
			if temp_url not in urls:
				urls.append(temp_url)
		i -= 1
	return urls

def giveresult(urls, domian):
	if urls == None:
		return None
	print("Find " + str(len(urls)) + " URL")
	content_url = ""
	content_subdomain = ""
	for url in urls:
		content_url += url + "\n"
		#print(url)
		
	subdomains = find_subdomain(urls, domian)
	print("\nFind " + str(len(subdomains)) + " Subdomain")
	for subdomain in subdomains:
		content_subdomain += subdomain + "\n"
		#print(subdomain)
	if args.outputurl != None:
		with open(args.outputurl, "a", encoding='utf-8') as fobject:
			fobject.write(content_url)
		print("\nOutput " + str(len(urls)) + " urls")
		print("Path:" + args.outputurl)
	if args.outputsubdomain != None:
		with open(args.outputsubdomain, "a", encoding='utf-8') as fobject:
			fobject.write(content_subdomain)
		print("\nOutput " + str(len(subdomains)) + " subdomains")
		print("Path:" + args.outputsubdomain)
	if args.outputleakinfo != None:
		with open(args.outputleakinfo, "a", encoding='utf-8') as fobject:
			for leak in leak_infos:
				fobject.write(str(leak) + '\n')
		print("\nOutput " + str(len(leak_infos)) + " leak_infos")
		print("Path:" + args.outputleakinfo)

if __name__ == "__main__":
	urllib3.disable_warnings()
	args = parse_args()
	if args.file == None:
		if args.deep is not True:
			urls = find_by_url(args.url)
			giveresult(urls, args.url)
		else:
			urls = find_by_url_deep(args.url)
			giveresult(urls, args.url)
	else:
		if args.js is not True:
			urls = find_by_file(args.file)
			giveresult(urls, urls[0])
		else:
			urls = find_by_file(args.file, js = True)
			giveresult(urls, urls[0])
