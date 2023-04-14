#!/usr/bin/python
__description__ = "Analyze mime encoded files to extract malicious data"
__author__="Gita Ziabari"
__version__="0.0.1"
__date__="04/24/2017"

"""
Source code put in Fidelis GitHub by Gita Ziabari, no Copyright
Use at your own risk
"""

from datetime import datetime,  timedelta
import os, sys, ihooks
import hashlib
from stat import *
import zipfile
import shutil

def format_date_pack():
    lastHourDateTime = datetime.now() - timedelta(minutes = 1)
    return lastHourDateTime.strftime('%Y%m%dT%H%M')

def import_from(name):
    loader = ihooks.BasicModuleLoader()
    m = loader.find_module(name, sys.path)
    if not m:
        raise ImportError, name
    m = loader.load_module(name, m)
    return m

def command(command_string):
    stdout = os.popen (command_string)
    return stdout.read()

def get_md5sum(file_path):
    hash_lib = None
    if os.path.exists(file_path):
       hash_md5 = hashlib.md5(open(file_path, "rb").read()).hexdigest()
    return hash_md5

def remove_file(file_path):
    if boolian_file_exist(file_path):
       os.remove(file_path)


def boolian_file_exist(file_name):
    return bool(file_exists := os.path.isfile(file_name))

def get_today():
    i = datetime.now()
    return ("%s-%02d-%02d" % (i.year, i.month, i.day))

def get_embedded_objects_run_foremost(attachment_files):
    today = get_today()
    extracted_files_lst = []
    for filepath in attachment_files:
        dir_name =  os.path.dirname(filepath)
        filename = os.path.basename(filepath).strip(".")
        output_dir = dir_name+filename+today
        if not  os.path.exists(output_dir):
           os.mkdir(output_dir)
        #command("foremost -i "+filepath+" -o "+output_dir +"  &> /dev/null")
        file_lst =  walktree(output_dir)
        for extracted_file in file_lst:
            if extracted_file == "audit.txt":
               continue
            extracted_file_path = f"{output_dir}/{extracted_file}"
            if extracted_file_path not in extracted_files_lst:
               extracted_files_lst.append(extracted_file_path)
    return extracted_files_lst         


def get_random():
    from random import choice
    from string import ascii_uppercase

    return ''.join(choice(ascii_uppercase) for _ in range(12))


def walktree(top, file_lst=[]):
    for f in os.listdir(top):
        pathname = os.path.join(top, f)
        mode = os.stat(pathname)[ST_MODE]
        if S_ISDIR(mode):
            # It's a directory, recurse into it
            walktree(pathname, file_lst)
        elif S_ISREG(mode):
            # It's a file, append it to file_lst
            if pathname in file_lst:
               continue
            file_lst.append(pathname)
        else:
            # Unknown file type, print a message
            print 'Skipping %s' % pathname
    return file_lst

def extract_zip(my_dir, my_zip): 
   zip_file = zipfile.ZipFile(my_zip, 'r')
   for files in zip_file.namelist():
       zip_file.extract(files, my_dir)
   zip_file.close()
   return my_dir


def get_iso_date_in_microseconds():
    i = datetime.now()
    return "%04d-%02d-%02dT%02d:%02d:%02d.%d" % (
        i.year,
        i.month,
        i.day,
        i.hour,
        i.minute,
        i.second,
        i.microsecond,
    )

def get_size(filename):
    st = os.stat(filename)
    return st.st_size

def clean_up_dir(mime_attachment_directory):
    if os.path.exists(mime_attachment_directory):
       shutil.rmtree(mime_attachment_directory)


if __name__ == "__main__":
   print "Hello World!"
