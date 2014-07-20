/*
 * AbstractCloudCrypto.hpp
 *
 *  Created on: Jul 19, 2014
 *      Author: doug
 */

#ifndef ABSTRACTCLOUDCRYPTO_HPP_
#define ABSTRACTCLOUDCRYPTO_HPP_

#include <string>
using namespace std;

#include <boost/filesystem/path.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
using namespace boost;

#include <crypto++/sha.h>
#include <crypto++/hex.h>
using namespace CryptoPP;

typedef unsigned char byte;

class AbstractCloudCrypto {

public:

	static const unsigned int KEYSIZE = SHA512::DIGESTSIZE;

	bool SaveKeyToFile(string outputPathString) {
		filesystem::path outputPath(outputPathString);
		return SaveKeyToFile(outputPath);
	}

	bool SaveKeyToFile(filesystem::path outputPath) {
		//hash
		//name
		//key
		//signature of name+plain file

		if (!IsInitialized())
			return false;

		try {
			property_tree::ptree properties;

			properties.put("KeyedFile", cipherFileNameBase + dataFileExtension);

			string symmetricKeyString = BytesToHexString(symmetricKey,
					sizeof(symmetricKey));
			properties.put("Key", symmetricKeyString);

			outputPath /= (cipherFileNameBase + keyFileExtension);

			write_json(outputPath.native(), properties);
		} catch (property_tree::ptree_error &e) {
			return false;
		}
		return true;
	}

	static string BytesToHexString(const byte* data,
			const unsigned int dataLength) {
		byte str[2 * dataLength + 1];

		HexEncoder e;

		HexEncoder encoder;
		encoder.Put(data, dataLength);
		encoder.MessageEnd();
		encoder.Get(str, 2 * dataLength);
		str[2 * dataLength] = 0;

		return string((char*) str);

	}

	static bool HexStringToBytes(string str, byte* data,
			const unsigned int dataLength) {

		if (dataLength < str.size() / 2)
			return false;

		HexDecoder decoder;
		decoder.Put((byte*) str.c_str(), str.size());
		decoder.MessageEnd();
		decoder.Get(data, str.size() / 2);

		return true;
	}

	const string& getCipherFileNameBase() const {
		return cipherFileNameBase;
	}

	const string& getDataFileExtension() const {
		return dataFileExtension;
	}

	const string& getKeyFileExtension() const {
		return keyFileExtension;
	}

protected:
	byte symmetricKey[KEYSIZE];
	string cipherFileNameBase;

	const string dataFileExtension = ".data.cld";
	const string keyFileExtension = ".key.cld";

	AbstractCloudCrypto() {}

	bool IsInitialized() {
		return !cipherFileNameBase.empty();
	}

	bool InitializeFromKeyFile(boost::filesystem::path keyFilePath) {

		if (!filesystem::exists(keyFilePath))
			return false;


		string keyHexString;
		string cipherFileNameBase;

		try {
			property_tree::ptree properties;
			property_tree::read_json(keyFilePath.native(), properties);

			keyHexString = properties.get<string>("Key");
			if (keyHexString.size() / 2 != KEYSIZE)
				return false;


			string keyedFileName = properties.get<string>("KeyedFile");
			cipherFileNameBase = keyedFileName.substr(0,
					keyedFileName.find_last_of(dataFileExtension));

		} catch (property_tree::ptree_error &e) {
			return false;
		}

		HexStringToBytes(keyHexString, symmetricKey, KEYSIZE);
		this->cipherFileNameBase = cipherFileNameBase;

		return true;
	}

};

#endif /* ABSTRACTCLOUDCRYPTO_HPP_ */
