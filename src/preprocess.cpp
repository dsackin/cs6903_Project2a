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
using namespace CryptoPP;

#include "CloudEncryptor.hpp"
#include "CloudDecryptor.hpp"

int main(int argc, char **argv) {

	filesystem::path outputPath("/home/doug/projects/cloud2/data");

	CloudEncryptor enc("file.txt", "this is my passphrase");
	enc.SaveKeyToFile(filesystem::path("/home/doug/projects/cloud2/data"));

	filesystem::path keyFilePath = outputPath / (enc.getCipherFileNameBase() + enc.getKeyFileExtension());


	filesystem::path dataFilePath = outputPath / (enc.getCipherFileNameBase() + enc.getDataFileExtension());
	CloudDecryptor::DecryptFile(keyFilePath, dataFilePath);


}
