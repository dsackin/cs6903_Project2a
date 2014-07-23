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

	CloudDecryptor() {}
	~CloudDecryptor() {}

	void DecryptFile(filesystem::path cipherFilePath) {

		if (!IsInitialized())
			throw CloudCryptoException(
					"Decryptor has not been initialized with a key");


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
		filesystem::path resultFilePath = cipherFilePath.parent_path() / plainFileNameString;

		stf->Detach(new FileSink(resultFilePath.c_str()));
		in.PumpAll();
	}

	static bool DecryptFile(filesystem::path keyFilePath, filesystem::path dataFilePath) {
		CloudDecryptor decryptor;
		decryptor.InitializeFromJsonKeyFile(keyFilePath);
		decryptor.DecryptFile(dataFilePath);

		return true;
	}


};

#endif /* CLOUDDECRYPTOR_HPP_ */
