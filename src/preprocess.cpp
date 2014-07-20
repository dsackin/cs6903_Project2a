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

	filesystem::path outputPath("/home/doug/projects/cloud2/data");

	filesystem::path in("/home/doug/projects/cloud2/data/test2.in");




	CloudEncryptor enc("test2.in", "this is my passphrase");
	enc.EncryptFile(in);

	filesystem::path keyFilePath = enc.SaveKeyToFile(outputPath);

	cout << keyFilePath.native() << "  " << enc.getSymmetricKeyAsHexString() << endl;

	filesystem::path dataFilePath = outputPath / (enc.getCipherFileNameBase() + enc.getDataFileExtension());
//	CloudDecryptor::DecryptFile(keyFilePath, dataFilePath);

	CloudDecryptor dec;
	dec.InitializeFromKeyFile(keyFilePath);

	cout << keyFilePath.native() << "  " << dec.getSymmetricKeyAsHexString() << endl;


}
