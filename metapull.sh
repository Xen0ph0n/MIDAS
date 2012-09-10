#!/bin/bash

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
