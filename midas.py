# midas.py 
# By Chris Clark 9/10/2012
# This is a early version of a program to automatically export to DB and scan
# the metadata from all incoming files. Also compute and tag each with MD5 hash
# for tracking and association.
#
# This requires: Python 2.7, Mongo DB, Pymongo, Yara 1.6, Yara Python 1.6, Exiftool, PyExiftool. 
# Install Mongo DB and use the default test DB, create a collection called "metadata" and you are good!
# Or change the settings below to reflect your database. 

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
# default localhost and default port for local database
connection = Connection('localhost', 27017)
# default is the test DB
db = connection.test
# default collection is metadata
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
	# Sleep function, program will run infinitly until killed (ctrl-c)
	while True:
		# Recursivly walk the target path and create a filename which is relative to the program
		for root, dirs, files in os.walk(pathtofiles):
    			for name in files: 
       				filename = os.path.join(root, name)
				# Run exiftool to extract all metadata from a file
				with exiftool.ExifTool() as et:
		    			metadata = et.get_metadata(filename)
				# call the md5sum function to get a hash, then use this as the OID to prevent duplicates in the database
				metadata[u'_id'] = md5sum(filename)
				# create a timestamp which will reflect the time the file is submitted to the database
       				metadata[u'File:DateTimeRecieved'] = now.strftime("%Y:%m:%d %H:%M:%S")
				# remove unwanted keys which were present in exiftool JSON
				del metadata[u'SourceFile']
				del metadata[u'File:FilePermissions']
				del metadata[u'File:Directory']
				del metadata[u'ExifTool:ExifToolVersion']
				# insert into mongo collection
				metadatacollection.insert(metadata)
				# convert the JSON dictionary to a string and run it through Yara
				matches = rules.match(data=str(metadata))
				# confirm successful datbase submission (duplicate Md5s will be ignored by mongo, no msg here)
				print "Metadata for " + filename + " added to database OK!"
				# Print yara hits, or none..**this will eventually export to logger**
				if matches:
					print "Yara Matches: "
					print  matches 
				else:
					print "No Yara Matches "
				# if -m switch is on, this will move each file to destination dir and remove them from scanning path
				if args['move']:
					#Make destination dir per agument if non existant
					if not os.path.exists(args['move']):
						os.makedirs(args['move'])
					shutil.move(filename, args['move'] + name)
					#Verify move for logs:
					print filename + " has been moved to " + args['move'] + name
					 
				# if -d switch is on, this will delete each file after scanning. !!BE CAREFUL WITH THIS!!
				if args['delete'] == True:
					os.remove(filename)
					# Confirm delete for logs.
					print filename + " has been deleted."
		#variable from 'sleep' arg input here, default 15 seconds
		time.sleep(sleeptime)

#standard catch to run main
if __name__ == "__main__":
	main()  
