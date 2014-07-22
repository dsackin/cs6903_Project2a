/*
 * preprocess.cpp
 *
 *  Created on: Jul 19, 2014
 *      Author: doug
 */

#include <iostream>
#include <string>
using namespace std;

#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/property_tree/ptree.hpp>
using namespace boost;

#include <crypto++/hex.h>
#include <crypto++/files.h>
#include <crypto++/mqueue.h>
using namespace CryptoPP;

#include "CloudEncryptor.hpp"
#include "CloudDecryptor.hpp"

int main(int argc, char **argv) {


//	ByteQueue bytes;
//
//	byte a[] = "this is the first part ";
//	byte b[] = "this is the second part ";
//	bytes.Put(a, sizeof(a));
//	bytes.Put(b, sizeof(b));
//	bytes.MessageEnd();
//
//	FileSink f("/home/doug/projects/cloud2/data/test.out", true);
//	bytes.CopyTo(f);
//	f.MessageEnd();

	filesystem::path outputPath("/home/doug/projects/cloud2/data");

	filesystem::path in("/home/doug/projects/cloud2/data/test2.in");




	CloudEncryptor enc("test2.in", "this is my passphrase");
	enc.EncryptFile2(in);

	filesystem::path keyFilePath = enc.SaveKeyToFile(outputPath);

	cout << keyFilePath.native() << "  " << enc.getSymmetricKeyAsHexString() << endl;

	filesystem::path dataFilePath = outputPath / (enc.getCipherFileNameBase() + enc.getDataFileExtension());
	CloudDecryptor::DecryptFile(keyFilePath, dataFilePath);

//	CloudDecryptor dec;
//	dec.InitializeFromKeyFile(keyFilePath);

//	cout << keyFilePath.native() << "  " << dec.getSymmetricKeyAsHexString() << endl;


}
