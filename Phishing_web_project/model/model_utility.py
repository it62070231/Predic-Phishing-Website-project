import asyncio
import base64
import datetime
import pickle
import urllib
import xml.etree.ElementTree as ET
from subprocess import Popen, PIPE
from urllib.parse import urlparse

import pandas as pd
import requests
import tldextract
import whois as whois
from bs4 import BeautifulSoup
from dateutil.relativedelta import relativedelta
from favicon import favicon
from requests_html import HTMLSession
from xgboost import XGBClassifier
import sklearn


async def to_find_having_ip_add(url):
    import string  # เพื่อใช้ hexdigits
    # ทำการหา :// แล้วทำการข้ามตำแหน่งไปข้างหลังเพื่อดูบริเวณที่น่าจะมีเลข IP
    index = url.find("://")
    split_url = url[index + 3:]
    # print(split_url)
    # หา / และตัดส่วนด้านหลังออกไปให้มีเฉพาะบริเวณที่น่าจะมีเลข IP
    index = split_url.find("/")
    split_url = split_url[:index]
    # print(split_url)
    split_url = split_url.replace(".", "")  # ลบจุดเพื่อให้เจอสามารถอ่านเป็นเลข IP ได้
    # print(split_url)
    counter_hex = 0  # ตัวนับเลขฐานสิบหก
    # ทำการหาเลขฐานสิบหก
    for i in split_url:
        if i in string.hexdigits + 'x':
            counter_hex += 1

    total_len = len(split_url)  # เช็คความยาวของ ip address
    having_IP_Address = 1  # กำหนดให้เป็นเชื่อใจได้ก่อน
    # เช็คจำนวนของเลขฐานสิบหก ถ้ามีมากกว่าหรือเท่ากับความยาว ip address ที่ตัดมาแสดงว่าเป็น Phishing
    if counter_hex >= total_len:
        having_IP_Address = -1

    return having_IP_Address


async def to_find_url_len(url):
    URL_Length = 1  # กำหนดให้เป็นเชื่อใจได้ก่อน
    # ตรวจความยาว URL เพื่อหาว่าเป็นน่าสงสัย (0) หรือ Phishing (-1) ไหม?
    if len(url) >= 75:
        URL_Length = -1
    elif len(url) >= 54 and len(url) <= 74:
        URL_length = 0

    return URL_Length


async def get_complete_URL(shortened_url):
    command_stdout = Popen(['curl', shortened_url], stdout=PIPE).communicate()[
        0]  # เปิดเว็บที่อยู่ในช่วง subprocess โดยทำการเก็บเป็น Obj ใน stdout เป็นตัวกลางสำหรับการดึงข้อมูลออกมา
    output = command_stdout.decode('utf-8')  # ทำการแปลงให้อยู่ในรูปแบบ utf-8
    href_index = output.find("href=")  # หาลิงค์ที่จะส่งต่อไปอีกเว็บ
    if href_index == -1:  # ถ้าหาไม่เจอจะลองหาที่เป็น HREF=
        href_index = output.find("HREF=")
    split_lst = output[href_index:].split('"')  # ทำการแยกในบรรทัด <a herf="..."> เป็น ["<a herf=", "...", ">"]
    expanded_url = split_lst[1]  # หาลิงค์ที่เชื่อมกับลิงค์ที่ย่อไว้
    return expanded_url


async def check_for_shortened_url(url):
    # บริการ shorten url ที่ยอดนิยมในปัจจุบัน
    famous_short_urls = ["bit.ly", "tinyurl.com", "goo.gl", "rebrand.ly", "t.co", "youtu.be", "ow.ly", "w.wiki",
                         "is.gd"]

    domain_of_url = url.split("://")[1]  # ทำการหา :// แล้วนำมาแค่ตัวข้างหลังทั้งหมด
    domain_of_url = domain_of_url.split("/")[0]  # ทำการหา / แล้วนำมาแค่ตัวข้างหน้า
    # ถ้ามีการใช้ shorten service ในส่วนนี้จะให้ status เป็น -1 และหาเว็บไซต์จริง แต่ถ้าไม่เป็น status จะเป็น 1
    status = 1
    if domain_of_url in famous_short_urls:
        status = -1

    complete_url = None
    if status == -1:
        complete_url = get_complete_URL(url)

    return (status, complete_url)


async def to_find_at(url):
    # ถ้ามี at จะเป็น -1 แต่ถ้าไม่มีจะเป็น 1
    having_at = 1
    index = url.find("@")
    if index != -1:
        having_at = -1

    return having_at


async def to_find_redirect(url):
    index = url.find("://")  # หา Index ของ :// ตัวแรก
    split_url = url[index + 3:]  # ตัด http:// หน้าสุด ออก
    index_slash = split_url.find("//")  # หา Index ของ //
    # ถ้ามี // ต่อ จะเป็น -1 แต่ถ้าไม่มีเป็น 1
    having_redirect = 1
    if index_slash != -1:
        having_redirect = -1

    return having_redirect


async def to_find_prefix(url):
    index = url.find("://")  # หา Index ของ :// ตัวแรก
    split_url = url[index + 3:]  # ตัด http:// หน้าสุดออก
    # print(split_url)
    index = split_url.find("/")  # หา ตัว / ตัวแรกในลิงค์
    split_url = split_url[:index]  # ตัดข้างหลัง / ทั้งหมด
    # print(split_url)
    having_or_in_domain = 1
    index = split_url.find("-")  # หา - ใน domain
    # print(index)
    if index != -1:  # ถ้ามี - ใน domain จะเป็น -1 แต่ถ้าไม่มีจะเป็น 1
        having_or_in_domain = -1

    return having_or_in_domain


async def to_find_multi_domains(url):
    url = url.split("://")[1]  # เอาข้างหลัง https:// หรือ http:// ทั้งหมด
    url = url.split("/")[0]  # เอาข้างหลัง / ทั้งหมด
    index_www = url.find("www.")  # หา index ของ www.
    split_url = url
    # ถ้าไม่มี www. จะไม่ตัดทิ้ง แต่ถ้ามีจะตัด
    if index_www != -1:
        split_url = url[index_www + 4:]
    # print(split_url)
    index_dot = split_url.rfind(".")  # หา Index ของ dot ของ ตำแหน่งหน้าสุด
    # print(index_dot)
    if index_dot != -1:  # ถ้ามี Index ของ dot จะทำการตัดให้เหลือข้างหน้า dot
        split_url = split_url[:index_dot]
    # print(split_url)
    counter = 0
    for i in split_url:  # loop หา . ใน split_url ทั้งหมด
        if i == ".":  # ถ้ามี . จะเพิ่มตัวนับ (counter) เพิ่ม 1
            counter += 1
    # ถ้า โดเมนย่อย มากกว่า 2 จุด จะเป็น -1 แต่ถ้าเท่ากับ 2 จะเป็น 0 และถ้าน้อยกว่า 2 จะเป็น 1
    having_multi_domain = 1
    if counter == 2:
        having_multi_domain = 0
    elif counter >= 3:
        having_multi_domain = -1

    return having_multi_domain


async def to_find_authority(url):
    index_https = url.find("https://")  # หา https:// ใน URL
    # valid_auth คือ ช่องทางว่าได้รับการยืนยันตัวตนกับทางไหน
    valid_auth = ["GeoTrust", "GoDaddy", "Network Solutions", "Thawte", "Comodo", "Doster", "VeriSign", "LinkedIn",
                  "Sectigo",
                  "Symantec", "DigiCert", "Network Solutions", "RapidSSLonline", "SSL.com", "Entrust Datacard",
                  "Google", "Facebook"]

    cmd = "curl -vvI " + url  # Command prompt ที่จะใช้ใน subprocess
    # ถ้าไม่มี https จะ return ออกเป็น -1
    having_auth = -1
    if index_https == -1:
        return having_auth

    stdout = Popen(cmd, shell=True, stderr=PIPE,
                   env={}).stderr  # ทำการเปิด shell เป็น subprocess แล้วรัน Command prompt
    output = stdout.read()  # อ่านผลลัพท์ที่ได้จากการทำ Popen
    std_out = output.decode('UTF-8')  # แปลงรูปแบบเป็น UTF-8
    # print(std_out)
    index = std_out.find("O=")  # หา Index ของ O=

    split = std_out[index + 2:]  # ตัดข้อความข้างหน้า O= ทั้งหมด
    index_sp = split.find(" ")  # หา Index ของ space ใน split
    cur = split[:index_sp]  # ตัดข้อความด้านหลังของ space ทั้งหมด

    index_sp = cur.find(",")  # หา Index ของ  , ใน ข้อความ
    if index_sp != -1:  # ถ้ามีจะตัดข้อความข้างหลัง , ทั้งหมด
        cur = cur[:index_sp]
        # print(cur)

    if cur in valid_auth:  # ถ้า cur มีอยู่ใน valid_auth จะได้ having_auth เป็น 1
        having_auth = 1

    return having_auth


async def check_abnormal_url(url):
    # ดึง domain name เพื่อออกมาตรวจสอบว่ามีใน url หรือไม่
    try:
        whois_res = whois.whois(url)
        if type(whois_res['domain_name']) is list:
            check = whois_res['domain_name'][1].lower()
        else:
            check = whois_res['domain_name'].lower()
        # ถ้าไม่มีแปลว่าเป็น phishing หรือ -1 ถ้ามีจะเป็น 1
        if whois_res is None or check not in url:
            return -1
        return 1
    except:
        return -1


async def get_source(url):
    """Return the source code for the provided URL.

    Args:
        url (string): URL of the page to scrape.

    Returns:
        response (object): HTTP response object from requests_html.
    """
    try:
        session = HTMLSession()
        response = session.get(url)
        return response

    except requests.exceptions.RequestException as e:
        print(e)


async def check_google_index(url):
    """Check if url have google index"""
    query = urllib.parse.quote_plus(url)  # ปรับ url ให้อยู่ในรูปที่สามารถ search ได้
    response = await get_source("https://www.google.com/search?q=" + query)  # ขอ HTTP response
    links = list(response.html.absolute_links)  # นำ link ที่เจอทั้งหมดใน search result มาใส่ list
    # กำหนด url ที่ไม่ต้องการ
    google_domains = ('https://www.google.',
                      'https://google.',
                      'https://webcache.googleusercontent.',
                      'http://webcache.googleusercontent.',
                      'https://policies.google.',
                      'https://support.google.',
                      'https://maps.google.')
    # นำ url ที่ไม่ต้องการออกจาก links
    for url1 in links[:]:
        if url1.startswith(google_domains):
            links.remove(url1)
    # ตรวจสอบว่าเจอ url ที่ต้องการหรือไม่
    if url in links:
        return 1
    return -1


async def check_submit_to_email(url):
    html_content = requests.get(url).text  # ตรวจสอบหน้าเว็บของ URL ทั้งหมด
    soup = BeautifulSoup(html_content, "lxml")
    # Check if no form tag
    form_opt = str(soup.form)  # ตรวจสอบว่า มี form หรือไม่
    index_mail = form_opt.find("mail()")  # หา Index ของ mail() ใน form
    if index_mail == -1:  # ถ้าไม่มี mail() ใน form ให้หา index ของ mailto:
        index_mail = form_opt.find("mailto:")

    if index_mail == -1:  # ถ้าไม่มี mailto: จะได้ 1 แต่ถ้ามีจะเป็น -1
        return 1
    return -1


async def existenceoftoken(url):
    # Assumption - pagename cannot start with this token
    index = url.find("//https")  # หา index ของ //https
    if index == -1:  # ถ้าไม่มี //https จะเป็น 1 แต่ถ้ามีจะเป็น -1
        return 1
    else:
        return -1


async def dregisterlen(url):
    try:
        web_response = whois.whois(url)  # เช็ครายละเอียด URL ใน whois
        creation_date = web_response["Creation Date"][0]  # เช็ควันเปิดของ URL
        expiry_date = web_response["Registry Expiry Date"][0]  # เช็ควันอายุการลงทะเบียนของ URL
        if expiry_date > creation_date + relativedelta(
                months=+ 12):  # ถ้าอายุวันลงทะเบียน มากกว่า วันที่เปิดของ URL จะเป็น 1 แต่ถ้าหมดอายุไปแล้ว จะเป็น -1
            return 1
        else:
            return -1
    except:  # ถ้าไม่เจอรายละเอียดใน whois จะเป็น -1
        return -1


async def sfh(url):
    """Server Form Handler"""
    html_text = requests.get(url).text  # เรียกข้อความจากหน้าเว็บ
    soup = BeautifulSoup(html_text, "lxml")  # จัดเรียงข้อมูลเป็น แนว lxml
    try:
        form = str(soup.form)  # หา form ในหน้าเว็บเป็น str
        action_index = form.find("action")  # หา index ของ action ในฟอร์ม
        if action_index != -1:  # ถ้าไม่มีคำว่า action จะเป็น 1 แต่ถ้ามีจะเข้า
            less_index = form[action_index:].find(">")  # ตัดข้างหน้าของ action ทั้งหมดและหา index ของ >
            form_split = form[action_index + 8:less_index - 1]  # ตัดใน form เหลือตรงกลาง
            if (form_split == "") or (
                    form_split == "about:blank"):  # ถ้า form ที่ได้มาไม่มี หรือเป็น about:blank จะเป็น -1
                return -1
            extract_response1 = tldextract.extract(url)  # extract ของ url ใน extract_response
            url_page = extract_response1.domain  # เก็บ domain หลังจาก ที่ได้ extract
            extract_response2 = tldextract.extract(form_split)  # extract form ลงใน extract_response2
            url_sfh = extract_response2.domain  # เก็บ domain ทั้งหมด ที่อยู่ใน extract
            if url_page in url_sfh:  # ถ้า domain ที่ได้มาจากหน้าเว็บ ตรงกับภายในฟอร์ม จะเป็น 1 แต่ถ้าไม่ จะเป็น 0
                return 1
            return 0
        else:
            return 1
    except:
        # ถ้าไม่เจอ หรือ error จะเป็น 1
        return 1


async def tags(url):
    raw_html = requests.get(url).text  # ดึง source code หน้าเว็บออกมาเป็น text
    soup = BeautifulSoup(raw_html, "lxml")  # แปลงรูปแบบของ html เป็น lxml

    # ทำการหาและนับจำนวนของ Meta, Script, Link
    meta_count = 0
    metas = soup.find_all('Meta')
    for meta in metas:
        u_meta = meta['href']
        current_page = tldextract.extract(u_meta)
        ul_page = current_page.domain
        if current_page not in ul_page:
            meta_count += 1

    stags_count = 0
    stags = soup.find_all('Script')
    for stag in stags:
        u_stag = stag['href']
        current_page = tldextract.extract(u_stag)
        u1page = current_page.domain
        if current_page not in u1page:
            stags_count += 1

    links_count = 0
    links = soup.find_all('Link')
    for link in links:
        u_link = link['href']
        current_page = tldextract.extract(u_link)
        u1page = current_page.domain
        if current_page not in u1page:
            links_count += 1

    meta_percent = 0
    script_percent = 0
    link_percent = 0
    # ถ้าไม่มี metas, script, links จะไม่หาอัตราส่วนของ meta, script, link แต่ถ้าเข้าจะหาอัตราส่วน
    if len(metas) != 0:
        meta_percent = (meta_count * 100) // len(metas)
    if len(stags) != 0:
        script_percent = (stags_count * 100) // len(stags)
    if len(links) != 0:
        link_percent = (links_count * 100) // len(links)
    # ถ้าเปอร์เซนต์รวมกันน้อยกว่า 17 จะเป็น 1 แต่ถ้าน้อยกว่าเท่ากับ 81 จะเป็น 0 และมากกว่านั้นจะเป็น -1
    if meta_percent + script_percent + link_percent < 17:
        return 1
    elif meta_percent + script_percent + link_percent <= 81:
        return 0
    else:
        return -1


async def redirect(url):
    url_request = requests.get(url)
    # เช็คจำนวนครั้งที่มีการ redirect
    redirect_count = len(url_request.history)
    if redirect_count >= 4:
        return -1
    else:
        return 1


async def check_statistical_report(url):
    # กำหนด header เพื่อนำไปใช้ทำ request ต่อไป
    headers = {
        'format': 'json',
    }

    # กำหนด url เพื่อนำไปใช้ทำ request ต่อไป
    def get_url_with_ip(URI):
        """Returns url with added URI for request"""
        url = "http://checkurl.phishtank.com/checkurl/"
        new_check_bytes = URI.encode()
        base64_bytes = base64.b64encode(new_check_bytes)
        base64_new_check = base64_bytes.decode('ascii')
        url += base64_new_check
        return url

    # ส่ง request ไปที่ phishtank
    def send_the_request_to_phish_tank(url, headers):
        """This function sends a request."""
        response = requests.request("POST", url=url, headers=headers)
        return response

    url = get_url_with_ip(url)
    r = send_the_request_to_phish_tank(url, headers)

    # นำ respones ที่ได้มาทำการหาว่าเป็น phishing หรือไม่
    def parseXML(xmlfile):
        # ตรวจสอบว่ามีรายการอยู่ใน phishtank หรือไม่
        root = ET.fromstring(xmlfile)
        verified = False
        for item in root.iter('verified'):
            if item.text == "true":
                verified = True
                break
        # ตรวจสอบว่าเป็น phishing หรือไม่
        phishing = False
        if verified:
            for item in root.iter('valid'):
                if item.text == "true":
                    phishing = True
                    break

        return phishing

    inphTank = parseXML(r.text)
    # print(r.text)

    if inphTank:
        return -1
    return 1


async def get_pagerank(url):
    pageRankApi = '8s0ow84s8s48sk4gww8k0c4so4808ook8g8so0ko'  # API Key
    extract_res = tldextract.extract(url)  # Extract domain, suffix in URL
    url_ref = extract_res.domain + "." + extract_res.suffix  # Join domain and suffix
    headers = {'API-OPR': pageRankApi}  # Set Key to header
    domain = url_ref  # Set Domain
    req_url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain  # Join Api PageRank and Domain URL
    request = requests.get(req_url, headers=headers)  # Request and Get From PageRank API
    result = request.json()  # Format to json
    # print(result)
    value = result['response'][0]['page_rank_decimal']  # Get Value to see Page rank Decimal
    if type(value) == str:  # If value is none set value is 0
        value = 0

    if value < 2:  # If value less than 2. It would be Phishing If it not. It will be Legitmate.
        return -1
    return 1


async def check_web_traffic(url):
    extract_res = tldextract.extract(url)  # Extract Domain and Suffix From URL
    url_ref = extract_res.domain + "." + extract_res.suffix  # Join Domain and Suffix become ref
    html_content = requests.get(
        "https://www.alexa.com/siteinfo/" + url_ref).text  # request Alexa to send information about URL
    soup = BeautifulSoup(html_content, "lxml")  # Set format with BeautifulSoup
    # Find Rank in Alexa
    value = str(soup.find('div', {'class': "rankmini-rank"}))[42:].split("\n")[0].replace(",", "")
    # If value is none it would be Phishing Website
    if not value.isdigit():
        return -1
    # If have value. it will check rank if value less than 100000 it will be legitmate website but if not it will be Suspicious
    value = int(value)
    if value < 100000:
        return 1
    return 0


async def check_dns_record(url):
    try:  # เช็คข้อมูลใน Whois ถ้ามีข้อมูลในนั้น จะเป็น 1 แต่ถ้าไม่มีจะเป็น -1
        whois_res = whois.whois(url)
        return 1
    except:
        return -1


async def check_age_of_domain(url):
    try:  # ถ้าไม่เจอ URL ในฐานข้อมูลจะเป็น -1
        whois_res = whois.whois(url)  # Check URL in WHOIS database
        if datetime.datetime.now() > whois_res["creation_date"][0] + relativedelta(
                months=+6):  # ถ้าเวลามากกว่า 6 เดือนจะเป็น 1 แต่ถ้าไม่จะเป็น -1
            return 1
        else:
            return -1
    except:
        return -1


async def check_iframe(url):
    html_content = requests.get(url).text  # Request เรียกหน้าเว็บของ url
    soup = BeautifulSoup(html_content, "lxml")  # จัดเรียงหน้าเว็บด้วย BeautifulSoup
    if str(soup.iframe).lower().find(
            "frameborder") == -1:  # หา frameborder จาก iframe ของตัวหน้าเว็บ ถ้าไม่มีเป็น 1 แต่ถ้ามีเป็น -1
        return 1
    return -1


async def check_rightclick(url):
    html_content = requests.get(url).text #Request หน้าเว็บของ URL
    soup = BeautifulSoup(html_content, "lxml") #แปลงให้อยู่ในรูปแบบ lxml
    # print(soup)
    if str(soup).lower().find("preventdefault()") != -1: #ถ้าเจอการใช้งาน preventdefault, event.button จะเป็น -1 แต่ถ้าไม่เจอเป็น 1
        return -1
    elif str(soup).lower().find("event.button==2") != -1:
        return -1
    elif str(soup).lower().find("event.button == 2") != -1:
        return -1
    return 1


async def check_onmouseover(url):
    try:
        html_content = requests.get(url).text #Request หน้าเว็บของ URL
        soup = BeautifulSoup(html_content, "lxml")
        if str(soup).lower().find('onmouseover="window.status') != -1: #ถ้าใช้ onmouseover กับ window.status จะเป็น -1 แต่ถ้าไม่จะเป็น 1
            return -1
        return 1
    except:
        return -1


async def check_favicon(url):
    extract_res = tldextract.extract(url) #Extract domain from URL
    url_ref = extract_res.domain

    favs = favicon.get(url) #find Favicon in this url
    # print(favs)
    match = 0
    for favi in favs: #loop check favicon in url
        url2 = favi.url #เก็บเว็บของ favicon
        extract_res = tldextract.extract(url2) #Extract หา domain ของ Favicon ตัวนั้น
        url_ref2 = extract_res.domain

        if url_ref in url_ref2: # เช็คว่า โดเมนของ Favicon กับ โดเมนของหน้าเว็บตรงกันหรือไม่
            match += 1

    if match >= len(favs)/2: #ถ้าตรงกันมากกว่าครึ่งจากทั้งหมด จะเป็น 1 แต่ถ้าไม่จะเป็น -1
        return 1
    return -1


async def check_request_URL(url):
    extract_res = tldextract.extract(url)  # Extract โดเมนของ URL
    url_ref = extract_res.domain

    # ทำการ subprocess โดยการดึง Api ของ hackertarget ว่ามี link ทั้งหมดกี่ลิงค์
    command_stdout = Popen(['curl', 'https://api.hackertarget.com/pagelinks/?q=' + url], stdout=PIPE).communicate()[0]
    links = command_stdout.decode('utf-8').split("\n")

    count = 0

    for link in links:  # วนเพื่อตรวจสอบว่า domain จาก link ที่เชื่อมกันได้ทำการใช้ domain เดียวกันหรือไม่ ถ้าไม่ใช่ นับ 1
        extract_res = tldextract.extract(link)
        url_ref2 = extract_res.domain

        if url_ref not in url_ref2:
            count += 1

    count /= len(links)  # เพื่อหาอัตราส่วนระหว่าง count และ link ทั้งหมด

    # ถ้าอัตราส่วนน้อยกว่า 0.22 จะเป็น legitmate แต่ถ้ามากกว่า 0.22 แต่น้อยกว่า 0.61 จะเป็น Suspicious และถ้ามากกว่านั้นจะเป็น phishing
    if count < 0.22:
        return 1
    elif count < 0.61:
        return 0
    else:
        return -1


async def url_validator(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc, result.path])
    except:
        return False


async def check_URL_of_anchor(url):
    try:  # ถ้าเว็บนั้นไม่มีแล้ว จะแสดงค่าเป็น 1
        extract_res = tldextract.extract(url)  # Extract domain ออกมาจาก URL
        url_ref = extract_res.domain
        html_content = requests.get(url).text  # เรียกหน้าเว็บของ URL
        soup = BeautifulSoup(html_content, "lxml")
        a_tags = soup.find_all('a')  # หา <a> ทั้งหมดใน soup

        if len(a_tags) == 0:  # ถ้าไม่มีแท็กเลยจะ Return เป็น legitmate
            return 1

        invalid = ['#', '#content', '#skip', 'JavaScript::void(0)']
        bad_count = 0
        for t in a_tags: #loop แท็กทั้งหมด
            link = t['href'] #หา href ใน a

            if link in invalid: #ถ้า href เข้าค่ายใน invalid จะนับ
                bad_count += 1

            if await url_validator(link): #เช็ค domain ใน <a> ว่ามี domain ของหน้าเว็บ ใช่อันเดียวกันหรือไหม
                extract_res = tldextract.extract(link)
                url_ref2 = extract_res.domain

                if url_ref not in url_ref2:
                    bad_count += 1
        bad_count /= len(a_tags) #หาอัตราส่วนระหว่าง bad count กับ a tags ทั้งหมด
        if bad_count < 0.31: #ถ้าน้อยกว่า 0.31 จะเป็น 1 แต่ถ้าน้อยกว่า 0.67 และมากกว่า 0.31 จะเป็น 0 ถ้ามากกว่านั้นจะเป็น -1
            return 1
        elif bad_count <= 0.67:
            return 0
        return -1
    except:
        return 1


async def extract_features(url):
    features_extracted = [0]*27
    phStatus, expanded = await check_for_shortened_url(url)
    features_extracted[2] = phStatus
    if expanded is not None:
        if len(expanded) >= len(url):
            url = expanded
    features_extracted[0] = await to_find_having_ip_add(url)
    features_extracted[1] = await to_find_url_len(url)
    features_extracted[3] = await to_find_at(url)
    features_extracted[4] = await to_find_redirect(url)
    features_extracted[5] = await to_find_prefix(url)
    features_extracted[6] = await to_find_multi_domains(url)
    features_extracted[7] = await to_find_authority(url)
    features_extracted[8] = await dregisterlen(url)
    features_extracted[9] = await check_favicon(url)
    features_extracted[10] = await existenceoftoken(url)
    features_extracted[11] = await check_request_URL(url)
    features_extracted[12] = await check_URL_of_anchor(url)
    features_extracted[13] = await tags(url)
    features_extracted[14] = await sfh(url)
    features_extracted[15] = await check_submit_to_email(url)
    features_extracted[16] = await check_abnormal_url(url)
    features_extracted[17] = await redirect(url)
    features_extracted[18] = await check_onmouseover(url)
    features_extracted[19] = await check_rightclick(url)
    features_extracted[20] = await check_iframe(url)
    features_extracted[21] = await check_age_of_domain(url)
    features_extracted[22] = await check_dns_record(url)
    features_extracted[23] = await check_web_traffic(url)
    features_extracted[24] = await get_pagerank(url)
    features_extracted[25] = await check_google_index(url)
    features_extracted[26] = await check_statistical_report(url)

    return features_extracted


async def preprocess_query(url):
    # Extract feature
    all_feature = [await extract_features(url)]

    # print(all_feature)

    # columns DataFrame
    df_columns = ['having_IP_Address', 'URL_Length', 'Shortining_Service',
                  'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
                  'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length',
                  'Favicon', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
                  'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
                  'Redirect', 'on_mouseover', 'RightClick', 'Iframe', 'age_of_domain',
                  'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index',
                  'Statistical_report']

    # Create DataFrame
    df = pd.DataFrame(all_feature, columns=df_columns)

    return df


def load_deployable_model(file):
    print("load a pre-trained model from...")
    print(file)
    with open(file, 'rb') as f:
        model = pickle.load(f)
    return model

