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

	CloudEncryptor(const string plainFileName, const byte *masterKey,
			unsigned int masterKeyLength) {

		DeducePlainFileName(plainFileName);
		DeriveSymmetricKey(plainFileName, masterKey, masterKeyLength);
		DeriveObfuscatedNameBase();
	}

	CloudEncryptor(const string plainFileName, const string masterPassPhrase) {

		DeducePlainFileName(plainFileName);

		byte phraseHash[KEYSIZE];

		SHA256 hash;
		hash.CalculateDigest(phraseHash, (byte*) masterPassPhrase.c_str(),
				masterPassPhrase.size());

		DeriveSymmetricKey(plainFileName, phraseHash, KEYSIZE);
		DeriveObfuscatedNameBase();
	}

	~CloudEncryptor() {
	}

	void EncryptFile2(filesystem::path plainFilePath) {

		if (!IsInitialized())
			throw CloudCryptoException(
					"Encryptor has not been initialized with a key");

		if (!exists(plainFilePath))
			throw CloudCryptoException("Path to plain file was not valid");

		byte iv[AES::BLOCKSIZE];

		AutoSeededRandomPool rng;
		rng.GenerateBlock(iv, AES::BLOCKSIZE);

		filesystem::path cipherFilePath = plainFilePath.parent_path()
				/ (cipherFileNameBase + getDataFileExtension());

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
	}

	const string& getPlainFileName() const {
		return plainFileName;
	}

protected:
	string plainFileName;

	/**
	 * Deduce whether the string provided as the plain file name is a path to
	 * a file or the name of the file. Test it as a path first. If it exists,
	 * then extract the filename. If not, just use the string as it arrived.
	 */
	void DeducePlainFileName(const string plainFile) {

		filesystem::path plainFilePath(plainFile);

		if (exists(plainFilePath))
			plainFileName = plainFilePath.filename().native();
		else
			plainFileName = plainFile;
	}

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
