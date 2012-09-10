#!/bin/bash
# Sloppy mess of a bash script with no alerting, but properly parses, adds 
# MD5 info and timestamp and adds to database all metadata from files in 
# directory then deletes the subject files.

for file in ../*.*
do
exiftool -j $file > "metadata.json"
MD5=`md5sum $file | cut -c 1-32`
date=`date --rfc-3339=date`
sed -n 'H;${x;s/"SourceFile": .*\n/"MD5" : "'$MD5'",\n  "DateRecieved" : "'$date'",\n  &/;p;}' metadata.json > metadata1.json
mongoimport -d test -c metadata --jsonArray metadata1.json
rm metadat*.json 
#rm "$file
done
