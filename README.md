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
SSDeep
PySSdeep

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
Version .07a
<br>
Latest Changes:<br>
Added ['YaraAlerts'] Key to Metadata JSON which will save the yara rule hits to the database entry for each file.
<br><br>
Installation: Install all of the prereqs listed above. <br> 
Place midas.py and midasyararules.yar in a directory which is NOT the path to be scanned. <br>
Configure your DB Server / DB / Collection info inside of midas.py (note it comes set up to connect to localhost:27017 DB = test Collection = metadata ) <br>
PROFIT!
<br><br>

- USAGE midas.py [options] /path/to/files 
- Currently the program works to extract exif data from all files in a given directory. 
- It computes an MD5hash and time stamp for each file and add that to the JSON 
- It then adds the metadata in json format to a mongo DB collection of your chosing 
- Then it will use the information in (-y TARG default:"midasyararules.yar") to perform detection based on the metadata. Detections will be logged at a WARNING level for easy ident and also added to the JSON data with key 'YaraAlerts' 
- It then has the ability to either (-d) delete or (-m) move files once scanned to a configurable destination.  
- It will then pause 15 seconds (configurable with -s) and repeat this process with no further interaction, logging all DB Submissions, and file moves/deletes 

Please contact me at chris@xenosec.org with any questions. 

USAGE Example: <br>
usage: midas.py [-h] [-d] [-y YARARULES] [-l LOGS] [-m MOVE] [-s SLEEP] Path <br><br>

Metadata Inspection Database Alerting System <br><br>

positional arguments: <br>
  Path                  Path to directory of files to be scanned (Required) <br><br>
optional arguments:<br>
  -h, --help            show this help message and exit <br>
  -d, --delete          Deletes files after extracting metadata (Default: False) <br>
  -S  --SSDeep         Perform ssdeep fuzzy hashing of files and store in DB (Default: False)<br>
  -y YARARULES, --yararules YARARULES <br>
                        Specify Yara Rules File (Default: ./midasyararules.yar)<br>
  -l LOGS, --logs LOGS  Midas logs Yara hits, DB Commits, and File Moves (Default: ./midas.log)<br>
  -m MOVE, --move MOVE  Where to move files to once scanned (Default: Files are Not Moved) <br>
  -s SLEEP, --sleep SLEEP Time in Seconds for Midas.py to sleep between scans (Default: 15 sec)<br>

<br>
<br>
LOGS Example:<br>
INFO:root:Starting Midas with the following args: {'yararules': './midasyararules.yar', 'logs': './midas.log', 'move': None, 'sleep': 15, 'Path': '../testmidas/', 'delete': True} <br>
INFO:root:2012:09:10 16:45:49: Metadata for july.swf MD5: ac97a9244a331ffd1f695d1a99485e5d added to database <br>
INFO:root:2012:09:10 16:45:49:../testmidas/july.swf has been deleted. <br>
INFO:root:2012:09:10 16:45:49: Metadata for 2.pdf MD5: 101c15e96c05c6ef289962f49f6dae87 added to database <br>
WARNING:root:2012:09:10 16:45:49: Yara Matches for 2.pdf: [MetaData_PDF_Test] MD5: 101c15e96c05c6ef289962f49f6dae87 <br>
INFO:root:2012:09:10 16:45:49:../testmidas/2.pdf has been deleted. <br>
INFO:root:2012:09:10 16:45:49: Metadata for 1.pdf MD5: 32d29ee5d36373a775c8f0776b2395bc added to database <br>
WARNING:root:2012:09:10 16:45:49: Yara Matches for 1.pdf: [MetaData_PDF_Test, MetaData_Author_OracleReports_Test] MD5: 32d29ee5d36373a775c8f0776b2395bc <br>
INFO:root:2012:09:10 16:45:49:../testmidas/1.pdf has been deleted.<br>
<br>
<br>
Info Inserted into database:
<br><br>
[_id] => 32d29ee5d36373a775c8f0776b2395bc<br>
[SSDeep] => 3072:TlijdBnn/V8zhltU+AqblNIrrN2Ywzmr35DUQKn:ynihrrRNIXN2YwzmzU<br>
[File:FileType] => PDF<br>
[File:FileSize] => 107474<br>
[File:DateTimeRecieved] => 2012:09:10 15:24:08 <br>
[PDF:PageCount] => 1<br>
[PDF:Title] => ntlwr_folio_logo_mpg3153683.pdf<br>
[PDF:Creator] => Oracle10gR2 AS Reports Services<br>
[File:MIMEType] => application/pdf<br>
[PDF:Author] => Oracle Reports<br>
[PDF:PDFVersion] => 1.4<br>
[PDF:Producer] => Oracle PDF driver<br>
[YaraAlerts] => [MetaData_PDF_Test, MetaData_Author_OracleReports_Test]<br>
[File:FileModifyDate] => 2012:09:10 14:41:14-04:00<br>
[PDF:ModifyDate] => 2012:07:10 07:39:29<br>
[PDF:CreateDate] => 2012:07:10 07:39:29<br>
[File:FileName] => 221.pdf<br>
[PDF:Linearized] => <br><br>

[_id] => ac97a9244a331ffd1f695d1a99485e5d<br>
[SSDeep] => 3072:QeORGrBzIqh1olop2dqvsQuiatQq+SnDwURYjcaY3o/GKZRDwcQ:5ORGrBzXQqvsQuztQq+qkjJY3o/3zMcQ<br>
[File:MIMEType] => application/x-shockwave-flash<br>
[File:DateTimeRecieved] => 2012:09:10 15:24:08<br>
[Flash:FileAttributes] => 25<br>
[XMP:Creator] => unknown<br>
[File:FileModifyDate] => 2012:09:10 14:41:02-04:00<br>
[XMP:Format] => application/x-shockwave-flash<br>
[Flash:Compressed] => 1<br>
[Flash:FlashVersion] => 14<br>
[File:FileSize] => 156778<br>
[XMP:Publisher] => unknown<br>
[Flash:ImageWidth] => 500<br>
[Flash:FrameCount] => 1<br>
[File:FileType] => SWF<br>
[File:FileName] => 22july.swf<br>
[Flash:ImageHeight] => 375<br>
[XMP:Date] => 2012:8:15<br>
[YaraAlerts] => None<br>
[XMP:Description] => http://www.adobe.com/products/flex<br>
[XMP:Title] => Adobe Flex 4 Application<br>
[Flash:Duration] => 0.041666666666667<br>
[Composite:ImageSize] => 500x375<br>
[Flash:FrameRate] => 24<br>
[XMP:Language] => EN<br>
<br>

What you see at the CLI Upon Execute:<br>
~/MIDAS$ python midas.py -m ../2 -s 30 ../testmidas/<br>
<br>
<br>
 Scanning all files recursively from here: ../testmidas/<br>
 Logging all information to: ./midas.log<br>
 Using Yara Rule file: ./midasyararules.yar<br>
 Sleeping for: 30 seconds between iterations<br>
 All files will be moved to: ../2 once scanned<br>
 SSDeep fuzzy hashing is set to: True<br>
 Delete after scanning is set to: False<br>
<br>
 This program will not terminate until you stop it. Enjoy!<br> 
