#!/usr/local/bin/python
__description__ = "Analyze mime encoded files to extract malicious data"
__author__="Gita Ziabari"
__version__="0.0.1"
__date__="04/24/2017"

"""
Source code put in Fidelis GitHub by Gita Ziabari, no Copyright
Use at your own risk
"""

import os, sys, re
import json
import magic
import shutil

sys.path.append("../src/")
from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *
from functions_email_parser import * 


def extract_files_given_dir(data_dir, mime_attachment_directory):
    json_data = {}
    attachments_lst = []
    file_lst = []
    today = get_today()
    if not  os.path.exists(mime_attachment_directory):
       os.mkdir(mime_attachment_directory)
    for root, dirs, files in os.walk(data_dir):
        for file_name in files:
            file_path = f"{root}/{file_name}"
            file_type = magic.from_file(file_path)
            if re.search("gzip compressed data", file_type):
                extracted_file_name = file_name.strip(".gz")
                extracted_file_path = f"{root}/{extracted_file_name}"
                if os.path.isdir(extracted_file_path):
                   shutil.rmtree(extracted_file_path)
                if os.stat(extracted_file_path):
                   os.remove(extracted_file_path)
                              #uncompress the file
                command(f"gunzip {file_path}")
                file_path = os.path.basename(file_path).strip(".gz")
                directory = f"{root}/{file_path}"
                try:
                  with open(directory) as f:
                         for line in f:
                             json_load = json.loads(line)
                             '''download attachments in the base64 mime''' 
                             get_mime_message(json_load, file_path)
                except:
                   continue

            elif re.search("Zip archive data", file_type):
               try:
                  extract_zip(mime_attachment_directory, file_path)
               except:
                  continue
            elif re.search('ASCII mail text', file_type):
                try:
                    get_attachments_mail_text(file_path, mime_attachment_directory)
                except:
                    continue
            elif re.search("ASCII English text", file_type):
                flag = 0 
                try:
                 with open(file_path) as f:
                   for line in f:
                        json_load = json.loads(line)
                        #download attachments in the base64 mime 
                        file_name = os.path.basename(file_path)
                        get_mime_message(json_load, file_name)
                        flag = 1
                   if flag ==0:
                       file_lst.append(file_path)
                except:
                   continue
            else:
                file_lst.append(file_path)
    dir_lst = walktree(mime_attachment_directory)
    return dir_lst+file_lst           


if __name__ == "__main__":
   print "Hello World!"
