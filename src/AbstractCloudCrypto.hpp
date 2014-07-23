/*
 * AbstractCloudCrypto.hpp
 *
 *  Created on: Jul 19, 2014
 *      Author: doug
 */

#ifndef ABSTRACTCLOUDCRYPTO_HPP_
#define ABSTRACTCLOUDCRYPTO_HPP_

#include <string>
#include <exception>
using namespace std;

#include <boost/filesystem/path.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
using namespace boost;

#include <crypto++/sha.h>
#include <crypto++/hex.h>
using namespace CryptoPP;

typedef unsigned char byte;

class CloudCryptoException: public std::exception {
public:
	CloudCryptoException(const char *message) :
			message(message) {
	}

	~CloudCryptoException() {
	}

	const char* what() const noexcept {
		return message;
	}
private:
	const char * message;

};

class AbstractCloudCrypto {

public:

	static const unsigned int KEYSIZE = SHA256::DIGESTSIZE;

	static string BytesToHexString(const byte* data,
			const unsigned int dataLength) {

		string out;
		MeterFilter meter(new StringSink(out));
		ArraySource in(data, dataLength, true, new HexEncoder(new Redirector(meter), false));

		return out;
	}

	static int HexStringToBytes(string str, byte* data,
			const unsigned int dataLength) {

		if (dataLength < str.size() / 2)
			return 0;

		MeterFilter meter(new ArraySink(data, dataLength));

		StringSource in(str, true, new HexDecoder(new Redirector(meter)));

		return meter.GetTotalBytes();
	}

	static bool IsHexString(string candidate) {
		regex hexDigitsOnly("^[[:xdigit:]]+$");
		return boost::regex_match(candidate, hexDigitsOnly);
	}

	const byte* getSymmetricKey() const {
		return symmetricKey;
	}

	const string getSymmetricKeyAsHexString() const {
		string keyHexString;
		return BytesToHexString(symmetricKey, KEYSIZE);
	}


protected:
	byte symmetricKey[KEYSIZE];

	AbstractCloudCrypto() {}

};

#endif /* ABSTRACTCLOUDCRYPTO_HPP_ */
