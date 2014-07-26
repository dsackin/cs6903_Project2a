#!/bin/bash -x

cd ~/projects/cloud2/demo
openssl sha256 upload/*

cat upload/small*

../bin/release/sackin-cloud.exe preprocess -k upload/small_key.txt --inputFile="upload/small_file.txt" -o upload

../bin/release/sackin-cloud.exe authorize -k upload/small_key.txt --inputFile="upload/small_file.txt" -o upload


../bin/release/sackin-cloud.exe preprocess -k "this is a password" --inputFile="upload/Grimms_Fairy_Tales.pdf" -n "GoodStory.pdf" -o upload

../bin/release/sackin-cloud.exe authorize -k "this is a password" -n "GoodStory.pdf" -o upload


../bin/release/sackin-cloud.exe preprocess -k upload/small_key.txt --inputFile="upload/small_file.txt" -o upload

../bin/release/sackin-cloud.exe authorize -k upload/small_key.txt --inputFile="upload/small_file.txt" -o upload

ls -l

openssl sha256 upload/*

ls -l download

cp upload/*key.cld download/.

