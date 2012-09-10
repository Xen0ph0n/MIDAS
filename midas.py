# midas.py 
# By Chris Clark 9/10/2012
# This is a early version of a program to automatically export to DB and scan
# the metadata from all incoming files. Also compute and tag each with MD5 hash
# for tracking and association.
import exiftool
import os
import shutil
import sys
import pymongo 
import hashlib
import datetime
import time
import yara
import argparse

# Database Connection Information
from pymongo import Connection
connection = Connection('localhost', 27017)
db = connection.test
metadatacollection = db.metadata

# Define Now to use in Timestamp
now = datetime.datetime.now()

# Argument Parser and Usage Help
parser = argparse.ArgumentParser(description='Metadata Inspection Database Alerting System')
parser.add_argument('Path', help='Path to directory of files to be scanned (Required)')
parser.add_argument('-d','--delete', action='store_true', help='Deletes files after extracting metadata (Default: False)', required=False)
parser.add_argument('-y','--yararules', default='./midasyararules.yar', help='Specify Yara Rules File (Default: ./midasyararules.yar)', required=False)
parser.add_argument('-m','--move', help='Where to move files to once scanned (Default: Files are Not Moved)', required=False)
parser.add_argument('-s','--sleep', type=int, default=15, help='Time in Seconds for Midas.py to sleep between scans (Default: 15 sec)', required=False)
args = vars(parser.parse_args())

# Set Path to files from Argument

pathtofiles = args['Path']
print "Path to be scanned: " +  pathtofiles 

# Time to sleep before iterating over target dir again
sleeptime = args['sleep']

# Location of Yara Rules File
rules = yara.compile(args['yararules'])

# Md5 Function
def md5sum(filename):
	md5 = hashlib.md5()
        with open(filename, 'rb') as f:
        	for chunk in iter(lambda: f.read(8192), b''):
 			md5.update(chunk)
	return md5.hexdigest()


# Main function which will loop as every X seconds
def main():
	while True:
		for root, dirs, files in os.walk(pathtofiles):
    			for name in files: 
       				filename = os.path.join(root, name)
				with exiftool.ExifTool() as et:
		    			metadata = et.get_metadata(filename)

				metadata[u'_id'] = md5sum(filename)
       				metadata[u'File:DateTimeRecieved'] = now.strftime("%Y:%m:%d %H:%M:%S")
				del metadata[u'SourceFile']
				del metadata[u'File:FilePermissions']
				del metadata[u'File:Directory']
				del metadata[u'ExifTool:ExifToolVersion']
				metadatacollection.insert(metadata)
				matches = rules.match(data=str(metadata))
				print "Metadata for " + filename + " added to database OK!"
				if matches:
					print "Yara Matches: "
					print  matches 
				else:
					print "No Yara Matches "
				if args['move']:
					if not os.path.exists(args['move']):
						os.makedirs(args['move'])
					shutil.move(filename, args['move'] + name) 
				if args['delete'] == True:
					os.remove(filename)
					print filename + " has been deleted."
		time.sleep(sleeptime)
if __name__ == "__main__":
	main()  
