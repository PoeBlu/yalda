The tool is designed to analyze the given files and extract malicious data out of the files.

Following are the proposed domains for using the tool:

->Data mining tool for extracting malicious Data such as URLs, Domains and embedded objects.

-> File Scanner for detecting if a file is malicious or suspicious.

-> Tool to obtain categorized data based on file format.

-> Base tool in any research that requires categorized information on the given file.

-> Testing tool to analyze detection ratio of malicious data in a product.

-> Please note that this tool is not an AV engine.

Scripts:

The following script are included in the package, please check regularly for updates:

trt_yalda_mime_attachment_data_miner.py

How to run the tools

Open confilg_file.py and add the following data in it to be able to run the scripts:

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

Requirement environment:

OS: Linux

Python: 2.7.6 +

Needed python modules

¥       magic, json, email

•       mimetypes

•       binascii

•       globe

•       mailbox

•       base64

•       pymongo
