MIDAS
=====

Metadata Inspection Database Alerting System

_____________________

This is a project to create a system to automate the inspection and datbasing of all Metadata information 
contained within all files destined for an orginization (generally via dumping the files which are attached 
to emails through the use of YARA, but could also be automated via netwitness or other full pcap tool). 
Alternativly this can be used to look for heuristic anomolys in existing collections of files both malicious
and begnin. 
This program uses PyExifData for extraction, and PyMongo to interface with a local Mongodb instance which will
store the extracted data for later querries and tracking. Alerting will take place via customized yara instance. 
Interaction between PyExifData and PyMongo will take place in JSON and the MD5 hash of each file will be used for
Identification. 

Please contact me at chris@xenosys.net with any questions. 