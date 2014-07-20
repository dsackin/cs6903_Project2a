/*
 * CloudDecryptor.hpp
 *
 *  Created on: Jul 19, 2014
 *      Author: doug
 */

#ifndef CLOUDDECRYPTOR_HPP_
#define CLOUDDECRYPTOR_HPP_

#include "AbstractCloudCrypto.hpp"

class CloudDecryptor: public AbstractCloudCrypto {

public:

	CloudDecryptor() {}
	~CloudDecryptor() {}

	void DecryptFile(filesystem::path dataFilePath) {

	}

	static bool DecryptFile(filesystem::path keyFilePath, filesystem::path dataFilePath) {
		CloudDecryptor decryptor;
		decryptor.InitializeFromKeyFile(keyFilePath);
		decryptor.DecryptFile(dataFilePath);

		return true;
	}


};

#endif /* CLOUDDECRYPTOR_HPP_ */
