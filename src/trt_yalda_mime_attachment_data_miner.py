#!/usr/local/bin/python

__description__ = "Analyze mime encoded files to extract malicious data"
__author__="Gita Ziabari"
__version__="0.0.1"
__date__="04/24/2017"

"""
Source code put in Fidelis GitHub by Gita Ziabari, no Copyright
Use at your own risk
"""

import sys, time

from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *


json_parser = import_from("functions_json_parser")
mime_analyzer = import_from("functions_email_parser")

if clean_up_mime_directory:
   clean_up_dir(mime_attachment_directory)


#get json data of the given files
attachment_files = json_parser.extract_files_given_dir(data_dir, mime_attachment_directory)


#print mime_attachments
mime_analyzer.analyze_mime_downloaded_files(attachment_files)

