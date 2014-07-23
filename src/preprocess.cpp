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

#include "common.h"

#include "CloudEncryptor.hpp"
#include "CloudDecryptor.hpp"

/**
 * Print a simple message describing the usage of this program
 * @param os - Reference to an output stream to which to write the usage message
 */
void printUsage(std::ostream &os) {
	os << "Usage: decrypt [-d <dictionaryPath>] [-c <cipherPath>] [-t <keyLength>]" << std::endl;
	os << "Attempts to decrypt a cipher text and identify the originating plain text from " << std::endl;
	os << "a dictionary of plain texts. " << std::endl;
	os << std::endl;
	os << std::endl;
	os << "This program requires the dictionary, cipher text, and key length as inputs. " << std::endl;
	os << "You may specify any or none of these on the command line. If no dictionary " << std::endl;
	os << "path is provided, the default dictionary embedded in the program will be " << std::endl;
	os << "assumed. The rest will be collected from stdin." << std::endl;
	os << std::endl;
	os << "-h - print this help message" << std::endl;
	os << "-k <key> or <keyFilePath> - key value or path to a file containing the key" << std::endl;
	os << "   candidate per line" << std::endl;
	os << "-f <cipherPath> - optional path to a text file containing a single line of " << std::endl;
	os << "   cipher text for the decryption attempt. If not provided as an argument, " << std::endl;
	os << "   this will be requested via stdin" << std::endl;
	os << "-n <keyLength> - optional integer length of a key phrase believed to be used " << std::endl;
	os << "   in the encryption. If not provided as an argument, this will be requested " << std::endl;
	os << "   via stdin" << std::endl;
	os << std::endl;
}


/**
 * Main program to execute the decrypt functionality using a provided cipher
 * text and plain text dictionary.
 *
 * @param argc - count of arguments
 * @param argv - array of c-style strings
 * @return
 */
int main(int argc, char **argv) {

	// process command line arguments
	processArguments(argc, argv, printUsage);

	bool test = isHexString("1234");
	test = isHexString("abcd");
	test = isHexString("0");
	test = isHexString("no1234");
	test = isHexString("011b");
	test = isHexString("bd123no");


	string b = "a4c321";
	byte c[b.size()];
	int bytesProcessed  = AbstractCloudCrypto::HexStringToBytes(b, c, b.size() / 2);

	b = "afdfsd";
	bytesProcessed = AbstractCloudCrypto::HexStringToBytes(b, c, b.size() / 2);
	 cout << "hello";

//
//	filesystem::path outputPath("/home/doug/projects/cloud2/data");
//
//	filesystem::path in("/home/doug/projects/cloud2/data/test.in");
//
//
//
//
//	CloudEncryptor enc("test.in", "this is my passphrase");
//	enc.EncryptFile2(in);
//
//	filesystem::path keyFilePath = enc.SaveKeyToJsonFile(outputPath);
//
//	cout << keyFilePath.native() << "  " << enc.getSymmetricKeyAsHexString() << endl;
//
//	filesystem::path dataFilePath = outputPath / (enc.getCipherFileNameBase() + enc.getDataFileExtension());
//	CloudDecryptor::DecryptFile(keyFilePath, dataFilePath);
//
////	CloudDecryptor dec;
////	dec.InitializeFromKeyFile(keyFilePath);
//
////	cout << keyFilePath.native() << "  " << dec.getSymmetricKeyAsHexString() << endl;


}
