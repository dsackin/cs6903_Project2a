/*
 * CloudEncryptor.hpp
 *
 *  Created on: Jul 19, 2014
 *      Author: doug
 */

#ifndef CLOUDENCRYPTOR_HPP_
#define CLOUDENCRYPTOR_HPP_

#include <crypto++/hmac.h>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/files.h>
#include <crypto++/osrng.h>
#include <crypto++/eax.h>

#include "AbstractCloudCrypto.hpp"

class CloudEncryptor: public AbstractCloudCrypto {

public:

	CloudEncryptor(const string plainFileName, const string masterKeyString) : plainFileName(plainFileName) {

		byte masterKeyBytes[KEYSIZE];

		if ((masterKeyString.length() == 2 * KEYSIZE) && IsHexString(masterKeyString)) {
			HexStringToBytes(masterKeyString, masterKeyBytes, KEYSIZE);
		} else {
			// treat the key string input as a passphrase and use its SHA256 hash as the key bytes
			SHA256 hash;
			hash.CalculateDigest(masterKeyBytes, (byte*) masterKeyString.c_str(),
					masterKeyString.size());
		}

		DeriveSymmetricKey(plainFileName, masterKeyBytes, KEYSIZE);
		DeriveObfuscatedNameBase();
	}

	~CloudEncryptor() {
	}

	void EncryptFile(filesystem::path plainFilePath, filesystem::path outputDirPath) {

		byte iv[AES::BLOCKSIZE];

		AutoSeededRandomPool rng;
		rng.GenerateBlock(iv, AES::BLOCKSIZE);
		memset(iv, 0x01, AES::BLOCKSIZE);


		filesystem::path cipherFilePath = outputDirPath / (cipherFileNameBase + getDataFileExtension());

		FileSink *out = new FileSink(cipherFilePath.c_str());
		out->PutWord16(sizeof(iv));
		out->Put(iv, sizeof(iv));

		CTR_Mode<AES>::Encryption aes_ctr_enc(getSymmetricKey(), KEYSIZE, iv);
		StreamTransformationFilter *stf = new StreamTransformationFilter(aes_ctr_enc, out);

		string plainFileName = plainFilePath.filename().native();
		unsigned short plainFileNameSize = plainFileName.size() + 1;
		stf->PutWord16(plainFileNameSize);
		stf->Put((byte*)plainFileName.c_str(), plainFileNameSize);

		FileSource in(plainFilePath.c_str(), true, stf);
		out->MessageEnd();

		cout << "Encryption Results" << endl;
		cout << "Plain file : " << plainFilePath.native() << endl;
		cout << "Encrypted file : " << cipherFilePath.native() << endl;

	}

	void ExportKey(filesystem::path outputDirPath) {

		string keyHexString = getSymmetricKeyAsHexString();
		filesystem::path keyFileName(getCipherFileNameBase() + getKeyFileExtension());

		filesystem::path keyFilePath = outputDirPath / keyFileName;

		StringSource in(keyHexString, true, new FileSink(keyFilePath.c_str()));

		cout << "Export Results" << endl;
		cout << "Plain file : " << getPlainFileName() << endl;
		cout << "Encrypted file : " << getCipherFileNameBase() + getDataFileExtension() << endl;
		cout << "Key file : " << keyFilePath << endl;
		cout << "key value : " << keyHexString << endl;
	}

	const string& getPlainFileName() const {
		return plainFileName;
	}

	const string& getCipherFileNameBase() const {
		return cipherFileNameBase;
	}

	const string& getDataFileExtension() {
		return dataFileExtension;
	}

	const string& getKeyFileExtension() {
		return keyFileExtension;
	}


protected:
	string plainFileName;
	string cipherFileNameBase;

	const string dataFileExtension = ".data.cld";
	const string keyFileExtension = ".key.cld";

	void DeriveSymmetricKey(const string plainFileName, const byte *masterKey,
			unsigned int masterKeyLength) {

		HMAC<SHA256> hmac(masterKey, KEYSIZE);
		hmac.CalculateDigest(symmetricKey, (byte*) plainFileName.c_str(),
				plainFileName.size());
	}

	void DeriveObfuscatedNameBase() {
		DeriveObfuscatedNameBase(plainFileName);
	}

	void DeriveObfuscatedNameBase(const string plainFileName) {
		byte nameHash[KEYSIZE];

		SHA256 hash;
		hash.CalculateDigest(nameHash, (byte*) plainFileName.c_str(),
				plainFileName.size());

		string nameHashString = BytesToHexString(nameHash, KEYSIZE);

		cipherFileNameBase = nameHashString.substr(0, 4) + "-"
				+ nameHashString.substr(4, 4) + "-"
				+ nameHashString.substr(nameHashString.size() - 8, 4) + "-"
				+ nameHashString.substr(nameHashString.size() - 4, 4);
	}

};

#endif /* CLOUDENCRYPTOR_HPP_ */
