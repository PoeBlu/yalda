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
import pymongo
from pymongo import MongoClient

sys.path.append("../src/")
from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *

client = MongoClient(localhost, port)
db = client[db_name]
phishing_domain_collection = db[collection_name]


def insert_data_in_database(domain_lst, file_path, md5, file_type, size):
       time = get_iso_date_in_microseconds()
       data_tbl = {'IngestTime': time,
                   'file_path':file_path,
                   'md5': md5,
                   'size': size,
                   'source': "phishing_domains",
                   'file_type': file_type,
                   'Indicator': domain_lst}
       inserted_id = db.phishing_domain.insert_one(data_tbl)


def get_phishing_domain():
    domain_tbl = []
    search_tbl = [{'source': "phishing_domains"}]
    for data in db.phishing_domain.find({'$and' : search_tbl},  no_cursor_timeout=True):
       domain_lst = domain = data.get("Indicator")
       for domain in domain_lst:
           if domain not in domain_tbl:
              domain_tbl.append(domain)
    return domain_tbl 

def get_md5_attachments():
    md5_tbl = []
    search_tbl = [{'source': "phishing_domains"}]
    for data in db.phishing_domain.find({'$and' : search_tbl},  no_cursor_timeout=True):
        md5 = domain = data.get("md5")
        if md5 not in md5_tbl:
           md5_tbl.append(md5)
    return md5_tbl

def get_entrie_data_database():
    data_tbl = []
    search_tbl = [{'source': "phishing_domains"}]
    for data in db.phishing_domain.find({'$and' : search_tbl},  no_cursor_timeout=True):
        if data not in data_tbl:
           data_tbl.append(data)
    return data_tbl

if __name__ == "__main__":
   aa = get_phishing_domain()
   print aa
