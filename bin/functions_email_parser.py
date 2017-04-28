#!/usr/local/bin/python

__description__ = "Analyze mime encoded files to extract malicious data"
__author__="Gita Ziabari"
__version__="0.0.1"
__date__="04/24/2017"

"""
Source code put in Fidelis GitHub by Gita Ziabari, no Copyright
Use at your own risk
"""

import magic
import os, sys, re
import json
import email
import mimetypes
import shutil
import binascii
import glob
import mailbox
import base64

sys.path.append("../src/")
from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *
from functions_database import * 

import random
import time

def get_mime_message(data, extracted_file):
    if not os.path.exists(mime_attachment_directory):
       os.mkdir(mime_attachment_directory)

    dir_lst = []
    dir_attachments = []
    msg_file = "/tmp/mime_msg"
    count = 0
    seen_dir = []
    for key in data:
            print key +"---"+str(data.get(key))
            time.sleep(3)
            #get mime message
            if key == "fullMessage":
               command("rm -f "+msg_file)
               mime_value = data.get(key)
               txt = open(msg_file, "w")
               txt.write(mime_value)
               txt.close()
               with open(msg_file) as fp:
                  msg = email.message_from_file(fp)
                  #new_dir = attachment_directory+extracted_file+str(count)
                  new_dir = mime_attachment_directory+extracted_file+"_"+str(count)
                  count+=1
                  if not os.path.exists(new_dir):
                     os.mkdir(new_dir)
                  counter = 1
                  for part in msg.walk():
                     if part.get_content_maintype() == 'multipart':
                        continue
                     filename = part.get_filename()
                     if not filename:
                        ext = mimetypes.guess_extension(part.get_content_type())
                        if not ext:
                           ext = '.bin'
                        filename = 'part-%03d%s' % (counter, ext)
                     counter+=1
                     with open(os.path.join(new_dir, filename), 'wb') as fp:
                               fp.write(part.get_payload(decode=True))
                     
                     #mime_attachments.setdefault(filename, new_dir)
                     file_list = os.listdir(new_dir)
                     for file_name in file_list:
                          file_path = new_dir+"/"+file_name
                          
                          if file_path in dir_attachments:
                             continue
                          if file_path.split(".")[-1]=="zip":
                             zip_file_name = file_path.strip(".zip")
                             zip_dir = zip_file_name+"_zip"
                             if os.path.exists(zip_dir):
                                      continue
                             
                             os.mkdir(zip_dir)
                             command("unzip "+file_path+" -d "+zip_dir)


def analyze_mime_downloaded_files(file_lst):
    attribute_tbl = {}
    domain_tbl = []
    suspicious_md5 = []
    count = 0
    for downloaded_file in file_lst:
            
            file_type_magic = magic.from_file(downloaded_file)
            file_type = downloaded_file.split(".")[-1]
            md5_hash = get_md5sum(downloaded_file)
            size = get_size(downloaded_file)
            base_dir = os.path.dirname(downloaded_file)
            if file_type == "zip":
               new_name = downloaded_file.strip(".zip")
               zip_dir =new_name+str(count)
               if os.path.exists(zip_dir):
                  continue
               try:
                 os.mkdir(zip_dir)
                 extracted_files = extract_zip(downloaded_file, zip_dir)
                 count+=1
                 for zip_file in extracted_files:
                   zip_file =  zip_dir+"/"+zip_file
                   md5sum = get_md5sum(zip_file)
                   extracted_file_type = magic.from_file(zip_file)
                   domain_lst = get_domain_lst(zip_file, extracted_file_type)
                   insert_data_in_database(domain_lst, zip_file, md5sum, file_type, size) 
               except:
                  continue
            else:
               domain_lst = get_domain_lst(downloaded_file, file_type_magic)
               insert_data_in_database(domain_lst, downloaded_file, md5_hash, file_type_magic, size) 


def get_domain_lst(downloaded_file, file_type):
    print downloaded_file
    domain_lst = []
    if re.search("ASCII text", file_type):
       file_format = downloaded_file.split(".")[-1]
       if file_format == "wsf":
           domain_lst = parse_wsf_file(downloaded_file)
       
    elif re.search("Rich Text Format data", file_type):
       blob = open(downloaded_file, 'r').read()
       string = ''.join(blob.splitlines())
       pattern = re.compile('68007400740070[\w\d]{,400}64006f0063')
       result = pattern.search(string)
       if result:
          link = ''.join(binascii.unhexlify(str(result.group(0))).split('\x00'))
          domain = (get_short_url(link)).rstrip("/")
          domain_lst.append(domain)      
          print domain
    elif re.search("PDF document", file_type):
       blob = open(downloaded_file, 'r').read()
       string = ''.join(blob.splitlines())
       match = re.search("/Type /Action/S /URI/URI \((http:\/\/[a-zA-Z_][a-zA-Z_0-9-./]*)\)\>\>endobj", string)
       if match:
          link =  match.group(1)
          domain = (get_short_url(link)).rstrip("/")
          domain_lst.append(domain)
    return domain_lst       

def get_short_url(url):
    """Return top two domain levels from URI"""
    format_lst = ["exe", "php", "html", "gif"]
    re_3986_enhanced = re.compile(r"""
        # Parse and capture RFC-3986 Generic URI components.
        ^                                    # anchor to beginning of string
        (?:  (?P<scheme>    [^:/?#\s]+): )?  # capture optional scheme
        (?://(?P<authority>  [^/?#\s]*)  )?  # capture optional authority
             (?P<path>        [^?#\s]*)      # capture required path
        (?:\?(?P<query>        [^#\s]*)  )?  # capture optional query
        (?:\#(?P<fragment>      [^\s]*)  )?  # capture optional fragment
        $                                    # anchor to end of string
        """, re.MULTILINE | re.VERBOSE)
    result = ""
    m_uri = re_3986_enhanced.match(url)
    if m_uri and m_uri.group("authority"):
        auth = m_uri.group("authority")
        paths = m_uri.group("path")
        path = paths.split("/")
        path = filter(lambda s: len(s) > 0, path)
        path_length = len(path)
        count = 1
        url_path = ""
        if path_length> 1:
           object_path1 = path[1].split(".")
           flag = 0
           for i in object_path1:
              if i in format_lst:
                 flag = 1
           if flag ==1:
              url_path = path[0]
           else:
              url_path = path[0]+"/"+path[1]

        scheme = m_uri.group("scheme")
        result = auth+"/"+url_path
    return result


def parse_wsf_file(zip_file):
    domain_lst=[]
    txt = open(zip_file, "r")
    lines = txt.readlines()
    txt.close()

    for line in lines:
        if not re.search("Array", line):
           continue
        try:
           list_array = line.split("Array(")
           array_data = ((list_array[1].split(";")[0]).strip(")")).split(",")
           for i in array_data:
               domain =  i.strip('"')
               domain_lst.append(domain)
        except:
           continue
    return domain_lst


def get_attachments_mail_text(filename, mime_attachment_directory):
    attachment_lst = []
    file_lst = []
    mb = mailbox.mbox(filename)
    nmes = len(mb)
    directory = os.path.dirname(filename)
    os.chdir(directory)
    for i in range(len(mb)):
        mes = mb.get_message(i)
	em = email.message_from_string(mes.as_string())
        print em

	subject = em.get('Subject')
	if subject.find('=?') != -1:
		ll = email.header.decode_header(subject)
		subject = ""
		for l in ll:
			subject = subject + l[0]

	em_from = em.get('From')
	if em_from.find('=?') != -1:
		ll = email.header.decode_header(em_from)
		em_from = ""
		for l in ll:
                    em_from = em_from + l[0]
        filename = mes.get_filename()
	
	# Puede tener filename siendo multipart???
	if em.is_multipart():
		for payl in em.get_payload():
			file_lst = extract_attachment(payl, mime_attachment_directory)
                        attachment_lst+=file_lst
	else:
            file_lst = extract_attachment(em, mime_attachment_directory)
            attachment_lst+=file_lst
    return attachment_lst    


def extract_attachment(payload, mime_attachment_directory):
        attachments = 0 #Count extracted attachment
        skipped = 0
        BLACKLIST = ('signature.asc', 'message-footer.txt', 'smime.p7s')
	filename = payload.get_filename()
        attachment_lst = []

	if filename is not None:
		if filename.find('=?') != -1:
			ll = email.header.decode_header(filename)
			filename = ""
			for l in ll:
				filename = filename + l[0]
			
		if filename in BLACKLIST:
			skipped = skipped + 1
			return

		content = payload.as_string()
		# Skip headers, go to the content
		fh = content.find('\n\n')
		content = content[fh:]

		# if it's base64....
		if payload.get('Content-Transfer-Encoding') == 'base64':
			content = base64.decodestring(content)

                attachment_lst.append(mime_attachment_directory+filename)
                 

		n = 1
		orig_filename = filename
		while os.path.exists(filename):
			filename = orig_filename + "." + str(n)
			n = n+1

		try:
			fp = open(mime_attachment_directory+filename, "w")
			fp.write(content)
		except IOError:
                        return
		finally:
			fp.close()	

		attachments = attachments + 1
	else:
		if payload.is_multipart():
			for payl in payload.get_payload():
                             extract_attachment(payl, mime_attachment_directory)
        return attachment_lst
if __name__ == "__main__":
   print "Hi there!"
  
