/*
 * CloudDecryptor.hpp
 *
 *  Created on: Jul 19, 2014
 *      Author: doug
 */

#ifndef CLOUDDECRYPTOR_HPP_
#define CLOUDDECRYPTOR_HPP_

#include <iostream>

#include <crypto++/aes.h>
#include <crypto++/modes.h>

#include "AbstractCloudCrypto.hpp"

class CloudDecryptor: public AbstractCloudCrypto {

public:

	~CloudDecryptor() {}

	void DecryptFile(filesystem::path cipherFilePath, filesystem::path outputDirPath) {

		byte iv[AES::BLOCKSIZE];
		memset(iv, 0x01, AES::BLOCKSIZE);

		unsigned short ivSize, plainFileNameSize;

		FileSource in(cipherFilePath.c_str(), false);

		in.Pump(2);
		in.GetWord16(ivSize);

		in.Pump(ivSize);
		in.Get(iv, ivSize);

		CTR_Mode<AES>::Decryption aes_ctr_dec(getSymmetricKey(), KEYSIZE, iv);
		StreamTransformationFilter *stf = new StreamTransformationFilter(aes_ctr_dec);
		in.Attach(stf);

		in.Pump(2);
		stf->GetWord16(plainFileNameSize);

		byte plainFileName[plainFileNameSize];
		in.Pump(plainFileNameSize);
		stf->Get(plainFileName, plainFileNameSize);
		cout << plainFileName << endl;

		string plainFileNameString((const char*)plainFileName);
		filesystem::path resultFilePath = outputDirPath / plainFileNameString;

		// check if we are trying to decrypt in the directory where the original
		// file name is already in use. If so, insert ".decrypted" before the
		// extension
		if (filesystem::exists(resultFilePath)) {
			filesystem::path outputFileName(plainFileNameString);
			string currentExtension = outputFileName.extension().native();
			outputFileName.replace_extension(filesystem::path(".decrypted." + currentExtension));
			resultFilePath = outputDirPath / outputFileName;
		}

		stf->Detach(new FileSink(resultFilePath.c_str()));
		in.PumpAll();
	}

	static bool DecryptFile(string keyString, filesystem::path cipherFilePath, filesystem::path outputDirPath) {

		byte symmetricKeyBytes[KEYSIZE];

		if ((keyString.length() == 2 * KEYSIZE) && IsHexString(keyString)) {
			HexStringToBytes(keyString, symmetricKeyBytes, KEYSIZE);
			CloudDecryptor decryptor(symmetricKeyBytes);
			decryptor.DecryptFile(cipherFilePath, outputDirPath);
			return true;
		}

		return false;
	}

protected:
	CloudDecryptor(byte *symmetricKey) : symmetricKey(symmetricKey) {}

};

#endif /* CLOUDDECRYPTOR_HPP_ */
