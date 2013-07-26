# midas.py v.22
# By Chris Clark 7/21/2013
# This is a early version of a program to automatically export to DB and scan
# the metadata from all incoming files. Also compute and tag each with MD5 hash
# for tracking and association.
#
# This requires: Python 2.7, Mongo DB, Pymongo, Yara 1.6, Yara Python 1.6, Exiftool, PyExiftool, ssdeep, and pydeep 
# Install Mongo DB and use the defaults and you are good!
# Or change the settings in midas-settings.cfg to reflect your custom database or server.
# Settings for logfile, and yararules file are also located in the midas-settings.cfg file. 

import ConfigParser, exiftool, os, shutil, sys, hashlib, datetime, time, argparse, logging, pymongo, json, urllib, urllib2
from multiprocessing import Pool

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
parser.add_argument('-d','--delete', action='store_true', help='Deletes files after scanning and extracting metadata (Default: False)', required=False)
parser.add_argument('-m','--move', help='Where to move files to once scanned (Default: Files are Not Moved)', required=False)
args = vars(parser.parse_args())

# Logging Configuration 
logsfile = config.get('settings','logs')
logging.basicConfig(filename=logsfile, level=logging.WARNING)
logging.info('Starting MIDAS with the following options: ' + str(args))

# Import PyDeep and Yara if needed
if config.get('settings','ssdeep') == 'True': import pydeep 
if config.get('settings','fullyara') == 'True': import yara

#keys to nuke from exiftool pulls and other globals
uselessexifkey = [u'SourceFile', u'File:FilePermissions', u'File:Directory', u'ExifTool:ExifToolVersion']
if config.get('settings', 'fullyara') == 'True':
	yararules = config.get('settings','yararules')
	rules = yara.compile(yararules)
sleeptime = config.get('settings','sleep')
pathtofiles = args['Path']

def printFuzzy():
	print "\n\n Scanning all files recursively with "+ str(config.get('settings','threads')) +" threads from here: " + pathtofiles 
	print " Logging all information to: " + logsfile
	print " Using Metadata Alert File: " + config.get('settings','badmetalist')
	print " Using Yara Rule file: " + yararules 
	if args['move']:
		print " All files will be moved to: " + args['move'] + " once scanned"
	else:
		print " Files will not be moved after scanning."
	print " SSDeep fuzzy hashing is set to: " + str(config.get('settings','ssdeep'))
	print " Full file Yara scanning is set to: " + str(config.get('settings','fullyara'))
	print " VirusTotal Hash Check is set to: " + str(config.get('settings', 'virustotal'))
	if config.get('settings','maliciousonly') == 'True':
		print " Only files which trigger an Alert or VT Hit will be submited to the Database"
	print " Delete after scanning is set to: " + str(args['delete'])
	if isinstance(sleeptime, (int, long)):
		print " Sleeping for: " + str(sleeptime) + " seconds between iterations"
		print " This program will not terminate until you stop it. "
	print "\n Created By: Chris Clark chris@xenosec.org https://github.com/xen0ph0n/MIDAS"
 
def sigfiles(filename):
	filein = open(filename, 'r').readlines()
	sigfile = []	
	for l in filein:
		line = l.rstrip()
		if line and not line.startswith('#'):
			sigfile.append(line)
	return sigfile

#Generate List of Bad Metadata to check against
badmetalist = sigfiles(config.get('settings','badmetalist'))

def md5sum(filename):
    fh = open(filename, 'rb')
    m = hashlib.md5()
    while True:
        data = fh.read(8192)
        if not data:
            break
        m.update(data)
    return m.hexdigest()

def buildFilelist(directory):
	filelist = [] 
	for root, dirs, files in os.walk(pathtofiles):
		for name in files: 
			filelist.append(os.path.join(root, name))
	return filelist

def metadataCheck(filename, md5):
	with exiftool.ExifTool() as et:
		metadata = et.get_metadata(filename)
	for key in uselessexifkey:
		del metadata[key]	
	hits = []	
	for key, value in metadata.iteritems():
		for sig in badmetalist:
			if sig == value:
				logging.critical(timestamp() + ": Bad Metadata Alert: " + key + ":" + value + " MD5:"+ md5)
				hits.append("Bad_Meta:" + key +  value)
	if hits:
		metadata[u'Metadata_Alerts'] = str(hits).replace("u'", "").replace("'",'')
	else: 
		metadata[u'Metadata_Alerts'] = 'None'
	return metadata

def timestamp():
	now = datetime.datetime.now()
	return now.strftime("%Y:%m:%d %H:%M:%S")


def yaraScan(filename, md5):
	if os.stat(filename).st_size > 0: #check to ensure no zero byte files are scanned 
		matches = rules.match(filename)
		if matches:
			logging.critical(timestamp() + ": Yara Alert: " + str(matches) + " MD5: " + md5)
			return matches
		else:
			return 'None'
	else:
		return 'None'

def inspectFile(filename):
	md5 = md5sum(filename)
	metadata = metadataCheck(filename, md5)
	metadata[u'md5'] = md5
	metadata[u'_id'] = md5
	metadata[u'File:DateTimeRecieved'] = timestamp()
	if config.get('settings','fullyara') == 'True': metadata[u'YaraAlerts'] = str(yaraScan(filename, md5))
	if config.get('settings','virustotal') == 'True': metadata[u'VirusTotal'] = vtapi(metadata[u'md5']) 
	if config.get('settings','virustotal') != 'True': metadata[u'VirusTotal'] = 'VirusTotal API Not Enabled'
	if config.get('settings','ssdeep') == 'True': metadata[u'SSDeep'] = ssdeep(filename)
	if config.get('settings','maliciousonly') == 'False':
		metadatacollection.update({'_id': md5}, metadata, upsert=True)
		logging.info(timestamp() + ": Metadata for " + os.path.basename(filename) + " MD5: " +md5 + " added to database")
	elif config.get('settings','maliciousonly') == 'True':
		if metadata[u'YaraAlerts'] != 'None' or metadata[u'Metadata_Alerts'] != 'None' or metadata[u'VirusTotal'][0].isdigit() == True:
			if not metadata[u'VirusTotal'].startswith('0'):
				metadatacollection.update({'_id': md5}, metadata, upsert=True)
				logging.info(timestamp() + ": Metadata for " + os.path.basename(filename) + " MD5: " +md5 + " added to database")
	if args['move']: moveFiles(args['move'], filename, os.path.basename(filename))
	if args['delete'] == True: deleteFiles(filename) 

def ssdeep(filename):
	return pydeep.hash_file(filename)

def moveFiles(movepath, filename, name):
	if not os.path.exists(movepath):
		os.makedirs(movepath)
	shutil.move(filename, movepath + name)
	logging.info(timestamp() + ":" + filename + " has been moved to " + movepath + name)

def deleteFiles(filename):
	os.remove(filename)
	logging.info(timestamp() + ":" + filename + " has been deleted.")

def vtapi(md5):
	url = "https://www.virustotal.com/vtapi/v2/file/report"
	parameters = {"resource": md5, "apikey": config.get('settings','vtapikey') }
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	try:
		VTjson = json.loads(response.read())
		#print VTjson
		if VTjson['response_code'] == 1 :
			vthitstat = str(VTjson['positives']) + '/' + str(VTjson['total']) + ' Detections on ' + str(VTjson['scan_date'])
			logging.critical(timestamp() + ": VirusTotal Alert: " + vthitstat + " MD5: " + md5)	
			return vthitstat		
		else :
			return "File Does Not Exist in VirusTotal"
	except Exception:
		return "VirusTotal API Error"
def main():

	printFuzzy()
	
	if sleeptime[0].isdigit():
		while True:
			filelist = buildFilelist(pathtofiles)
			if config.get('settings', 'threads')[0].isdigit():
				pool = Pool(processes = int(config.get('settings','threads')))
				pool.map(inspectFile, filelist)
			else:
				for f in filelist:
					inspectFile(f)
			time.sleep(int(sleeptime))
	else:
			filelist = buildFilelist(pathtofiles)
			if config.get('settings', 'threads')[0].isdigit():
				pool = Pool(processes = int(config.get('settings','threads')))
				pool.map(inspectFile, filelist)
			else:
				for f in filelist:
					inspectFile(f)

if __name__ == "__main__":
	main()  