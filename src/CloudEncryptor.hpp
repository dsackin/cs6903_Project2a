/*
 * CloudEncryptor.hpp
 *
 *  Created on: Jul 19, 2014
 *      Author: doug
 */

#ifndef CLOUDENCRYPTOR_HPP_
#define CLOUDENCRYPTOR_HPP_

#include <crypto++/hmac.h>

#include "AbstractCloudCrypto.hpp"

class CloudEncryptor: public AbstractCloudCrypto {

public:

	CloudEncryptor(const string plainFileName, const byte *masterKey,
			unsigned int masterKeyLength) :
			plainFileName(plainFileName) {

		DeriveSymmetricKey(plainFileName, masterKey, masterKeyLength);
		DeriveObfuscatedNameBase(plainFileName);
	}

	CloudEncryptor(const string plainFileName, const string masterPassPhrase) :
			plainFileName(plainFileName) {

		byte phraseHash[KEYSIZE];

		SHA512 hash;
		hash.CalculateDigest(phraseHash, (byte*) masterPassPhrase.c_str(),
				masterPassPhrase.size());

		DeriveSymmetricKey(plainFileName, phraseHash, KEYSIZE);
		DeriveObfuscatedNameBase(plainFileName);
	}

	~CloudEncryptor() {
	}

	bool EncryptFile() {
		return true;
	}

protected:
	string plainFileName;

	void DeriveSymmetricKey(const string plainFileName, const byte *masterKey,
			unsigned int masterKeyLength) {

		HMAC<SHA512> hmac(masterKey, KEYSIZE);
		hmac.CalculateDigest(symmetricKey, (byte*) plainFileName.c_str(),
				plainFileName.size());
	}

	void DeriveObfuscatedNameBase(const string plainFileName) {
		byte nameHash[KEYSIZE];

		SHA512 hash;
		hash.CalculateDigest(nameHash, (byte*) plainFileName.c_str(),
				plainFileName.size());

		string nameHashString = BytesToHexString(nameHash, KEYSIZE);

		cout << nameHashString << endl;

		cipherFileNameBase = nameHashString.substr(0, 4) + "-"
				+ nameHashString.substr(4, 4) + "-"
				+ nameHashString.substr(nameHashString.size() - 8, 4) + "-"
				+ nameHashString.substr(nameHashString.size() - 4, 4);
	}

};

#endif /* CLOUDENCRYPTOR_HPP_ */
