MIDAS
=====

Metadata Inspection Database Alerting System

_____________________

This is a project to create a system to automate the inspection and databasing of all Meta data information
contained within all files destined for an organization (generally via dumping the files which are attached
to emails through the use of YARA, but could also be automated via netwitness, other full pcap tool, or just
to iterate through file servers looking for suspicious files). <br>

Alternatively, this can be used to look for heuristic anomalies in existing collections of files both malicious
and benign. <br><br>

MIDAS Requires: <br>
Yara 1.6 
Yara Python 1.6
MongoDB 2.0+
PyMongo 2.2+
Python 2.7
Exiftool 9.0+
PyExiftool 

<br><br>
This program uses PyExifData for extraction, and PyMongo to interface with a local Mongodb instance which will
store the extracted data for later queries and tracking. Alerting takes place via yara instance.
<br><br>

Interaction between PyExifData and PyMongo will take place in JSON and the MD5 hash of each file is computed in python then used as the OID in Mongo to prevent duplicate entries into the DB.
<br><br>
All options except for the target DB can be configured via commandline. ( path to scan, -s (sleeptime between iterations), -d (delete after Scan), -m TARG (move after scan), -l TARG (Log file), -y TARG (Yara rule file) 
<br><br> 
DB is configured to connect to localhost & default port, db = test, collection = metadata. This can be changed in midas.py

<br><br>
Version .05a
<br><br>
Installation: Install all of the prereqs listed above. Place midas.py and midasyararules.yar in a directory which is NOT the path to be scanned. <br> PROFIT!
<br><br>

- USAGE midas.py [options] /path/to/files 
- Currently the program works to extract exif data from all files in a given directory. 
- It computes an MD5hash and time stamp for each file and add that to the JSON 
- It then adds the metadata in json format to a mongo DB collection of your chosing 
- Then it will use the information in (-y TARG default:"midasyararules.yar") to perform detection based on the metadata. Detections will be logged at a WARNING level for easy ident. 
- It then has the ability to either (-d) delete or (-m) move files once scanned to a configurable destination.  
- It will then pause 15 seconds (configurable with -s) and repeat this process with no further interaction, logging all DB Submissions, and file moves/deletes 

Please contact me at chris@xenosys.net with any questions. 
