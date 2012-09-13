# midas.py v.12
# By Chris Clark 9/13/2012
# This is a early version of a program to automatically export to DB and scan
# the metadata from all incoming files. Also compute and tag each with MD5 hash
# for tracking and association.
#
# This requires: Python 2.7, Mongo DB, Pymongo, Yara 1.6, Yara Python 1.6, Exiftool, PyExiftool, (ssdeep, and pyssdeep. 
# Install Mongo DB and use the defaults and you are good!
# Or change the settings in midas-settings.cfg to reflect your custom database or server.
# Settings for logfile, and yararules file are also located in the midas-settings.cfg file. 

import ConfigParser
import exiftool
import os
import shutil
import sys 
import hashlib
import datetime
import time
import yara
import argparse
import logging
import pymongo

# Import DB Config from midas-settings.cfg
config = ConfigParser.SafeConfigParser()
config.read("midas-settings.cfg")

dbserver = config.get('midasdb','server')
dbport = int(config.get('midasdb','port'))
dbdb = config.get('midasdb','db')
dbcoll = config.get('midasdb','collection')

# Database Connection Information
from pymongo import Connection
metadatacollection = Connection(dbserver, dbport)[dbdb][dbcoll]

# Argument Parser and Usage Help
parser = argparse.ArgumentParser(description='Metadata Inspection Database Alerting System')
parser.add_argument('Path', help='Path to directory of files to be scanned (Required)')
parser.add_argument('-d','--delete', action='store_true', help='Deletes files after extracting metadata (Default: False)', required=False)
parser.add_argument('-S','--SSDeep', action='store_true', help='Perform ssdeep fuzzy hashing of files and store in DB (Default: False)', required=False)
parser.add_argument('-f','--fullyara', action='store_true', help='Scan the entriety of each file with Yara (Default: Only Metadata is scanned)', required=False)
parser.add_argument('-m','--move', help='Where to move files to once scanned (Default: Files are Not Moved)', required=False)
parser.add_argument('-s','--sleep', type=int, default=15, help='Time in Seconds for Midas.py to sleep between scans (Default: 15 sec)', required=False)
args = vars(parser.parse_args())

# Logging Configuration 
logsfile = config.get('settings','logs')
logging.basicConfig(filename=logsfile, level=logging.INFO)
logging.info('Starting Midas with the following args: ' + str(args))

# Time to sleep before iterating over target dir again
sleeptime = args['sleep']

# Import PySSDeep if needed
if args['SSDeep'] == True:
	from ssdeep import ssdeep

# Location of Yara Rules File
yararules = config.get('settings','yararules')
rules = yara.compile(yararules)

# Set Path to files from Argument
pathtofiles = args['Path']

# Return Warm and Fuzzy to CLI while magic happens in the background
print "\n\n Scanning all files recursively from here: " + pathtofiles 
print " Logging all information to: " + logsfile
print " Using Yara Rule file: " + yararules  + "\n Sleeping for: " + str(sleeptime) + " seconds between iterations"
if args['move']:
	print " All files will be moved to: " + args['move'] + " once scanned"
else:
	print " Files will not be moved after scanning."
print " SSDeep fuzzy hashing is set to: " + str(args['SSDeep'])
print " Full file Yara scanning is set to: " + str(args['fullyara'])
print " Delete after scanning is set to: " + str(args['delete'])
print "\n This program will not terminate until you stop it. Enjoy! \n Created By: Chris Clark: chris@xenosec.org or @xenosec"
 
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
				md5 = md5sum(filename)
				metadata[u'_id'] = md5
				# create a timestamp which will reflect the time the file is submitted to the database
       				now = datetime.datetime.now()
				timestamp = now.strftime("%Y:%m:%d %H:%M:%S")
				metadata[u'File:DateTimeRecieved'] = timestamp
				# if (-S) flag is set, perform SSDeep hash and insert into JSON
				if args['SSDeep'] == True:
					metadata[u'SSDeep'] = ssdeep().hash_file(filename)
				# remove unwanted keys which were present in exiftool JSON
				del metadata[u'SourceFile']
				del metadata[u'File:FilePermissions']
				del metadata[u'File:Directory']
				del metadata[u'ExifTool:ExifToolVersion']
				# convert the JSON dictionary to a string and run it through Yara
				matches = rules.match(data=str(metadata))
				# Scan full file with yara if -f flag is set, this can be slow
				if args['fullyara'] == True:
					fullmatches = rules.match(filename)
					matches.extend(fullmatches)
				# Print yara hits, or none..**this will eventually export to logger**
				if matches:
					metadata[u'YaraAlerts'] = str(matches)
					logging.warning(timestamp + ": Yara Matches for " + name + ": " + str(matches) + " MD5: " + md5)
				else:
					metadata[u'YaraAlerts'] = "None"
					logging.debug(timestamp + ": No Yara Matches for " + name + " MD5: " + md5)
			
				# insert into mongo collection
				metadatacollection.insert(metadata)
				# confirm successful datbase submission (duplicate Md5s will be ignored by mongo, no msg here)
				logging.info(timestamp + ": Metadata for " + name + " MD5: " +md5 + " added to database")
				# if -m switch is on, this will move each file to destination dir and remove them from scanning path
				if args['move']:
					#Make destination dir per agument if non existant
					if not os.path.exists(args['move']):
						os.makedirs(args['move'])
					shutil.move(filename, args['move'] + name)
					#Verify move for logs:
					logging.info(timestamp + ":" + filename + " has been moved to " + args['move'] + name)
					 
				# if -d switch is on, this will delete each file after scanning. !!BE CAREFUL WITH THIS!!
				if args['delete'] == True:
					os.remove(filename)
					# Confirm delete for logs.
					logging.info(timestamp + ":" + filename + " has been deleted.")
		#variable from 'sleep' arg input here, default 15 seconds
		time.sleep(sleeptime)
#standard catch to run main
if __name__ == "__main__":
	main()  
