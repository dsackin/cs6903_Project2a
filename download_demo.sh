#!/bin/bash -x

cd ~/projects/cloud2/demo

ls -l upload/*.enc.cld

openssl sha256 upload/*.enc.cld

ls -l download/*.enc.cld

openssl sha256 download/*.enc.cld

cat upload/small*

../bin/release/sackin-cloud.exe recover -k download/814a-2ea6-9822-5e24.key.cld --inputFile=download/814a-2ea6-9822-5e24.enc.cld -o download

cat download/fa8d-57aa-20fc-dbd9.key.cld
../bin/release/sackin-cloud.exe recover -k 547051aed33fd4cb27a7c95c4148d9f38717fb742dfe8d467210f2d6d4e12c15 --inputFile="download/fa8d-57aa-20fc-dbd9.enc.cld" -o download

ls -l upload/*.pdf upload/*.txt

openssl sha256 upload/*.pdf upload/*.txt

ls -l download/*pdf download/*.txt

openssl sha256 download/*.pdf download/*.txt