MIDAS
=====

Metadata Inspection Database Alerting System

_____________________

This is a project to create a system to automate the inspection and databasing of all Meta data information
contained within all files destined for an organization (generally via dumping the files which are attached
to emails through the use of YARA, or BRO, but could also be automated via netwitness, other full pcap tool, or just
to iterate through file servers looking for suspicious files). This tool will extract metadata, alert on badness
scan with Yara, SSDEEP, and submit hashes to VirusTotal.<br>

Alternatively, this can be used to look for heuristic anomalies in existing collections of files both malicious
and benign.

MIDAS Requires: 
===
Yara 1.6+ <br>
Yara Python 1.6+ <br>
MongoDB 2.0+ <br>
PyMongo 2.2+ <br>
Python 2.7 <br>
Exiftool 9.0+ <br>
PyExiftool  <br><br>
*Optional if you want SSDeep fuzzy Hashing* <br>
SSDeep <br>
Pydeep <br>

This program uses PyExifData for extraction of metadata, and PyMongo to interface with a local Mongodb instance which will
store the extracted data for later queries and tracking. Files and extracted metadata are also scanned by Yara and alerts 
are written out to logs, and along with MD5hashes and a SSDeep fuzzy hash are placed in the JSON which is sent to the Database.
Latest Changes
====
Version .21a
<br>
Fully Refactored the codebase. Moved many args to the midas-settings.cfg file. Added VirusTotal functionality (Requires Premium API). Moved to a list of bad Metadata vs Yara Rules. Added Threads for multiprocessing to increase speed. Ability to slectivly database only files which alert on Metadata, Yara, or VirusTotal.<br>
Version .11a
<br>
Added midas-settings.cfg file for database config and yararules/log file config, that way I can keep it in one place to make a tool to search that DB later, and it keeps the user out of the source of midas.py<br>
Version .10a
<br>
Added full file yara scanning, this can be resource intensive if you have a lot of rules. (-f or -fullyara). It will alert to logs at warning level and push all alerts for a file into the DB in the JSON<br>
Version .09a
<br>
Added SSDeep Fuzzy Hashing with (-S or -SSDeep) flag, saved in JSON to ['SSDeep'] Key. New dependencies: ssdeep/pyssdeep (if you dont want to use this you can just never use the flag and delete the include ssdeep from the head of midas.py)
<br>
Version .07a
<br>
Added ['YaraAlerts'] Key to Metadata JSON which will save the yara rule hits to the database entry for each file.
Installation:
====
Install all of the prereqs listed above. <br> 
Place midas.py, midasdb.cfg, and midasyararules.yar in a directory which is NOT the path to be scanned. <br>
Configure your DB Server / DB / Collection info inside of midas-settings.cfg (note it comes set up to connect to localhost:27017 DB = test Collection = metadata ) <br>
You can also set a YaraRules file and designate a log file in midas-settings.cfg (default is midasyararules.yar and midas.log)
PROFIT!
<br>

- Currently the program works to extract exif data from all files in a given directory. 
- It computes an MD5hash and time stamp for each file and add that to the JSON 
- All Metadata will be checked against badmetalist.txt (or file of your selection, one entry per line) matches trigger alerts.
- Optional: Files SSDeep Scanned
- Optional: Files scanned with Yara (Hits result in an alert)
- Optional: Files scanned with VirusTotal (Hits result in an alert)
- It then adds the metadata in json format to a mongo DB collection of your chosing (selectivly only malicious files)
- It then has the ability to either (-d) delete or (-m) move files once scanned to a configurable destination.  
- It will then pause 15 seconds (configurable or off (default)) and repeat this process with no further interaction, logging all DB Submissions (or only malicious, and file moves/deletes 

Please contact me at chris@xenosec.org with any questions. 

midas-settings.cfg
===
<br>
```
#Config File for MIDAS
#DB info below:
[midasdb]
server: localhost
port: 27017
db: test
collection: metadata

#General Settings

[settings]

#Path to log file, default midas.log
logs: midas.log

#Database data only on files who set off an alert (Yara/Metadata/Virustotal) (default: database data from all files)
maliciousonly: False

#list of Malicious Metadata to Alert on
badmetalist: badmetalist.txt

#Number of Processes to spawn to increase processing speed of samples
threads: 4

#Sleep time in seconds if using internal loop to recurse over input directory (Set to 'off' to disable)
sleep: off

#Perform ssdeep fuzzy hashing of files and store in DB
ssdeep: True

#Scan the entriety of each file with Yara Rules
fullyara: True
yararules: midasyararules.yar

#Submit Hash of scanned file to VirusTotal Records Detections (Only hash is submitted requires Premium API Key)
virustotal: False
vtapikey: <----PREMIUM APIKEYHERE----->

```


_____________________

USAGE Example: 
====
```
usage: midas.py [-h] [-d] [-m MOVE] Path

Metadata Inspection Database Alerting System

positional arguments:
  Path                  Path to directory of files to be scanned (Required)

optional arguments:
  -h, --help            show this help message and exit
  -d, --delete          Deletes files after scanning and extracting metadata
                        (Default: False)
  -m MOVE, --move MOVE  Where to move files to once scanned (Default: Files
                        are Not Moved)

```

What you see at the CLI Upon Execute:
===
```
python midas.py ../yaragenerator/greencat/


 Scanning all files recursively with 4 threads from here: ../yaragenerator/greencat/
 Logging all information to: midas.log
 Using Metadata Alert File: badmetalist.txt
 Using Yara Rule file: midasyararules.yar
 Files will not be moved after scanning.
 SSDeep fuzzy hashing is set to: True
 Full file Yara scanning is set to: True
 VirusTotal Hash Check is set to: False
 Only files which trigger an Alert or VT Hit will be submited to the Database
 Delete after scanning is set to: False

 Created By: Chris Clark chris@xenosec.org https://github.com/xen0ph0n/MIDAS
 ```

LOGS Example:
===
```
CRITICAL:root:2013:07:23 20:18:43: Bad Metadata Alert: EXE:OriginalFilename:SMAgent.exe MD5:57e79f7df13c0cb01910d0c688fcd296
WARNING:root:2013:07:23 20:18:43: Yara Alert: [Win_Trojan_APT_APT1_Greencat] MD5: 57e79f7df13c0cb01910d0c688fcd296
WARNING:root:2013:07:23 20:18:43: Yara Alert: [Win_Trojan_APT_APT1_Greencat] MD5: 6570163cd34454b3d1476c134d44b9d9
WARNING:root:2013:07:23 20:18:43: Yara Alert: [Win_Trojan_APT_APT1_Greencat] MD5: 871cc547feb9dbec0285321068e392b8
```

Info Inserted into database:
===
```
{ "_id" : "6570163cd34454b3d1476c134d44b9d9", 

"EXE:FileSubtype" : 0, 
"EXE:OriginalFilename" : "SMAgent.exe", 
"md5" : "6570163cd34454b3d1476c134d44b9d9", 
"Metadata_Alerts" : "[Bad_Meta:EXE:OriginalFilenameSMAgent.exe]", 
"YaraAlerts" : "[Win_Trojan_APT_APT1_Greencat]", 
"VirusTotal" : "38/46 Detections on 2013-04-23 10:33:40",
"File:DateTimeRecieved" : "2013:07:23 20:22:13", 
"EXE:InternalName" : "SMAgent", 
"EXE:ProductName" : "SoundMAX service agent", 
"File:MIMEType" : "application/octet-stream", 
"File:FileAccessDate" : "2013:07:23 20:22:13-04:00", 
"EXE:InitializedDataSize" : 6144, 
"File:FileModifyDate" : "2013:05:04 17:14:27-04:00", 
"EXE:CompanyName" : "Analog Devices, Inc.", 
"EXE:FileVersionNumber" : "3.2.6.0", 
"EXE:FileVersion" : "3,2,6,0", 
"File:FileSize" : 14336, 
"EXE:CharacterSet" : "04E4", 
"EXE:MachineType" : 332, 
"EXE:FileOS" : 262148, 
"EXE:LegalTrademarks" : "", 
"EXE:ProductVersion" : "3,2,6,0", 
"EXE:ObjectFileType" : 1, 
"EXE:PrivateBuild" : "", 
"File:FileType" : "Win32 EXE", 
"EXE:UninitializedDataSize" : 0, 
"File:FileName" : "c196cac319e5c55e8169b6ed6930a10359b3db322abe8f00ed8cb83cf0888d3b", 
"EXE:ImageVersion" : 0, 
"EXE:SpecialBuild" : "", 
"EXE:OSVersion" : 4, 
"EXE:PEType" : 267, 
"EXE:TimeStamp" : "2010:10:21 02:51:09-04:00", 
"EXE:FileFlagsMask" : 63, 
"EXE:LegalCopyright" : "Copyright ? 2002", 
"EXE:LinkerVersion" : 6, 
"EXE:FileFlags" : 0, 
"EXE:Subsystem" : 2, 
"EXE:FileDescription" : "SoundMAX service agent component", 
"EXE:EntryPoint" : 10940, 
"EXE:SubsystemVersion" : 4, 
"EXE:CodeSize" : 7680, 
"EXE:Comments" : "", 
"File:FileInodeChangeDate" : "2013:05:04 17:14:27-04:00", 
"EXE:LanguageCode" : "0409", 
"SSDeep" : "384:nenM1a3iNIusg21SNdhBN6uh1HbLu2Jxkd:nen4/IuPbNNN3HzTkd", 
"EXE:ProductVersionNumber" : "3.2.6.0" }

{ "_id" : "57e79f7df13c0cb01910d0c688fcd296", 
"EXE:FileSubtype" : 0, 
"EXE:OriginalFilename" : "SMAgent.exe", 
"md5" : "57e79f7df13c0cb01910d0c688fcd296", 
"Metadata_Alerts" : "[Bad_Meta:EXE:OriginalFilenameSMAgent.exe]", 
"YaraAlerts" : "[Win_Trojan_APT_APT1_Greencat]", 
"VirusTotal" : "40/46 Detections on 2013-04-23 10:26:13", 
"File:DateTimeRecieved" : "2013:07:23 20:30:09", 
"EXE:InternalName" : "SMAgent", 
"EXE:ProductName" : "SoundMAX service agent", 
"File:MIMEType" : "application/octet-stream", 
"File:FileAccessDate" : "2013:07:23 20:30:09-04:00", 
"EXE:InitializedDataSize" : 5632, 
"File:FileModifyDate" : "2013:05:04 17:14:10-04:00", 
"EXE:CompanyName" : "Analog Devices, Inc.", 
"EXE:FileVersionNumber" : "3.2.6.0", 
"EXE:FileVersion" : "3, 2, 6, 0", 
"File:FileSize" : 14336, 
"EXE:CharacterSet" : "04E4", 
"EXE:MachineType" : 332, 
"EXE:FileOS" : 262148, 
"EXE:LegalTrademarks" : "", 
"EXE:ProductVersion" : "3, 2, 6, 0", 
"EXE:ObjectFileType" : 1, 
"EXE:PrivateBuild" : "", 
"File:FileType" : "Win32 EXE", 
"EXE:UninitializedDataSize" : 0, 
"File:FileName" : "3.exe", 
"EXE:ImageVersion" : 0, 
"EXE:SpecialBuild" : "", 
"EXE:OSVersion" : 4, "EXE:PEType" : 267, 
"EXE:TimeStamp" : "2011:11:17 02:22:44-05:00", 
"EXE:FileFlagsMask" : 63, 
"EXE:LegalCopyright" : "Copyright ? 2002", 
"EXE:LinkerVersion" : 6, 
"EXE:FileFlags" : 0, 
"EXE:Subsystem" : 2, 
"EXE:FileDescription" : "SoundMAX service agent component", 
"EXE:EntryPoint" : 10927, 
"EXE:SubsystemVersion" : 4, 
"EXE:CodeSize" : 7680, 
"EXE:Comments" : "", 
"File:FileInodeChangeDate" : "2013:05:04 17:14:10-04:00", 
"EXE:LanguageCode" : "0409", 
"SSDeep" : "192:atM4PNAjfK0jbbRClEw8CmwxvsENQsPQUeqsP1oyng6Lu4/JxxfnDsPsVL2:atTFiK0tCNmcvsEexUa1JLu2Jxnh", 
"EXE:ProductVersionNumber" : "3.2.6.0" }
```
_____________________

Copyright & License Info:
====
MIDAS is copyrighted by Chris Clark 2013. 
Contact me at Chris@xenosys.org

MIDAS is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

MIDAS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with MIDAS. If not, see http://www.gnu.org/licenses/.
