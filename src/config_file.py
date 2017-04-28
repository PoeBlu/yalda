#!/usr/local/bin/python


#place the directory of bin folder here
bin_dir = "../bin"

'''indicate directory of files to be parsed---place all of your files in this directory for analysis'''
data_dir = "<Place the directory with files in this directory>"

'''indicate directory to download mail attachments'''
mime_attachment_directory = "<Directory to download email attachments>"

'''clean up mail directory prior executing the script, set it to 1 if you would like to clean upthe directory prior executing it'''
clean_up_mime_directory = 0

'''specify mongodb credentials here'''
localhost = "<IP address of mongodb server>"
port = <integer format - indicate the port>
db_name = 'amfm_db'
collection_name = 'phishing_domain'

