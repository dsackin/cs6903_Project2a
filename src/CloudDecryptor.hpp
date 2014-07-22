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

		filesystem::path resultFilePath = cipherFilePath.parent_path() / "decrypted";

		byte iv[AES::BLOCKSIZE];
		memset(iv, 0x01, AES::BLOCKSIZE);

		unsigned short ivSize, plainFileNameSize;

//		std::ifstream is(cipherFilePath.native());
//		is >> ivSize;
//		is >> iv;
//
//		FileSource in(is, true);

		FileSource in(cipherFilePath.c_str(), false);
		cout << in.MaxRetrievable() << endl;

		in.Pump(2);
		cout << in.MaxRetrievable() << endl;

		in.GetWord16(ivSize);
		in.Pump(ivSize);
		cout << in.MaxRetrievable() << endl;
		in.Get(iv, ivSize);

//		is.seekg(18);

		cout << in.MaxRetrievable() << endl;

		// stf->GetWord16(plainFileNameSize);

		// byte plainFileName[plainFileNameSize];
		// stf->Get(plainFileName, plainFileNameSize);


		CTR_Mode<AES>::Decryption aes_ctr_dec(getSymmetricKey(), KEYSIZE, iv);


		StreamTransformationFilter *stf = new StreamTransformationFilter(aes_ctr_dec, new FileSink(resultFilePath.c_str()));
		in.Attach(stf);
		in.PumpAll();
//		is.close();

	}

	static bool DecryptFile(filesystem::path keyFilePath, filesystem::path dataFilePath) {
		CloudDecryptor decryptor;
		decryptor.InitializeFromKeyFile(keyFilePath);
		decryptor.DecryptFile(dataFilePath);

		return true;
	}


};

#endif /* CLOUDDECRYPTOR_HPP_ */
