/**
 * cloud.cpp
 *
 *  Created on: July 29, 2014
 *      Author: Douglas Sackin, NYU CS6903, Summer 2014
 */

#include <iostream>
#include <strstream>
#include <string>
#include <set>
#include <map>
using namespace std;

#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/program_options.hpp>
#include <boost/regex.hpp>
using namespace boost;
namespace po = boost::program_options;

#include <crypto++/hex.h>
#include <crypto++/files.h>
#include <crypto++/mqueue.h>
#include <crypto++/sha.h>
#include <crypto++/hmac.h>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/files.h>
#include <crypto++/osrng.h>
#include <crypto++/gcm.h>
using namespace CryptoPP;

typedef unsigned char byte;

class CloudCrypto {

protected:
	static const unsigned int KEYSIZE = SHA256::DIGESTSIZE;
	static const unsigned int TAGSIZE = 16;

	static const unsigned short KEYTEST = 43981;

	byte symmetricKey[KEYSIZE];

	string plainFileName;
	string encryptedFileNameBase;

	const string encryptedFileExtension = ".enc.cld";
	const string encryptedSignedFileExtension = ".encsign.cld";
	const string decryptedFileExtension = ".dec.cld";
	const string decryptedValidatedFileExtension = ".decval.cld";
	const string keyFileExtension = ".key.cld";

public:

	CloudCrypto(const string plainFileName, const string masterKeyString) :
			plainFileName(plainFileName) {

		byte masterKeyBytes[KEYSIZE];

		if ((masterKeyString.length() == 2 * KEYSIZE)
				&& IsHexString(masterKeyString)) {
			HexStringToBytes(masterKeyString, masterKeyBytes, KEYSIZE);
		} else {
			// treat the key string input as a passphrase and use its SHA256 hash as the key bytes
			SHA256 hash;
			hash.CalculateDigest(masterKeyBytes,
					(byte*) masterKeyString.c_str(), masterKeyString.size());
		}

		DeriveSymmetricKey(plainFileName, masterKeyBytes, KEYSIZE);
		DeriveEncryptedFileNameBase();
	}

	~CloudCrypto() {
	}

	void EncryptFile(filesystem::path plainFilePath,
			filesystem::path outputDirPath) {

		byte iv[AES::BLOCKSIZE];

		AutoSeededRandomPool rng;
		rng.GenerateBlock(iv, AES::BLOCKSIZE);

		filesystem::path encryptedFilePath = outputDirPath / GetEncryptedFileName();

		FileSink *out = new FileSink(encryptedFilePath.c_str());
		out->PutWord16(sizeof(iv));
		out->Put(iv, sizeof(iv));

		CTR_Mode<AES>::Encryption aes_ctr_enc(GetSymmetricKey(), KEYSIZE, iv);
		StreamTransformationFilter *stf = new StreamTransformationFilter(aes_ctr_enc, out);

		// write endian and key test value
		stf->PutWord16(KEYTEST);

		string plainFileName = plainFilePath.filename().native();
		unsigned short plainFileNameSize = plainFileName.size() + 1;
		stf->PutWord16(plainFileNameSize);
		stf->Put((byte*) plainFileName.c_str(), plainFileNameSize);

		FileSource in(plainFilePath.c_str(), true, stf);
		out->MessageEnd();

		cout << "Encryption Results" << endl;
		cout << "Plain file : " << plainFilePath.native() << endl;
		cout << "Encrypted file : " << encryptedFilePath.native() << endl << endl;

	}

	void EncryptAndSignFile(filesystem::path plainFilePath,
			filesystem::path outputDirPath) {

		cout << "ERROR: Encryption with authentication not implemented" << endl;

//		byte iv[AES::BLOCKSIZE];
//
//		AutoSeededRandomPool rng;
////		rng.GenerateBlock(iv, AES::BLOCKSIZE);
//		memset(iv, 0x01, sizeof(iv));
//
//
//		filesystem::path encryptedFilePath = outputDirPath / GetEncryptedFileName(true);
//
//		try {
//			GCM<AES>::Encryption gcm_aes_enc;
//			gcm_aes_enc.SetKeyWithIV(GetSymmetricKey(), KEYSIZE, iv, sizeof(iv));
//
//			AuthenticatedEncryptionFilter ef(gcm_aes_enc,
//					new FileSink(encryptedFilePath.c_str()),
//					false,
//					TAGSIZE		// tag size
//					/* MAC_AT_END */
//					); // AuthenticatedEncryptionFilter
//
//			// write the iv to the authenticated but not encrypted channel
//			ef.ChannelPut(AAD_CHANNEL, iv, sizeof(iv));
//			ef.ChannelMessageEnd(AAD_CHANNEL);
//
//			// Authenticated data *must* be pushed before
//			//  Confidential/Authenticated data. Otherwise
//			//  we must catch the BadState exception
//			ef.ChannelPutWord16(DEFAULT_CHANNEL, KEYTEST);
//
//			string plainFileName = plainFilePath.filename().native();
//			unsigned short plainFileNameSize = plainFileName.size() + 1;
//
//			ef.ChannelPutWord16(DEFAULT_CHANNEL, plainFileNameSize);
//			ef.ChannelPut(DEFAULT_CHANNEL, (byte*) plainFileName.c_str(),
//					plainFileNameSize);
//
////			MessageQueue queue(AES::BLOCKSIZE);
//			byte bytes[AES::BLOCKSIZE];
//
//			FileSource in(plainFilePath.c_str(), false);
////			in.Attach(new Redirector(ef));
////			in.PumpAll();
//
//			while (in.AnyRetrievable()) {
//				unsigned short bytesRetrieved = in.Get(bytes, sizeof(bytes));
//				ef.ChannelPut(DEFAULT_CHANNEL, bytes, bytesRetrieved);
//			}
//			ef.ChannelMessageEnd(DEFAULT_CHANNEL);
//
//			cout << "Encryption Results" << endl;
//			cout << "Plain file : " << plainFilePath.native() << endl;
//			cout << "Encrypted and Signed file : " << encryptedFilePath.native() << endl;
//
//		} catch (CryptoPP::Exception& e) {
//			cerr << "Caught Exception..." << endl;
//			cerr << e.what() << endl;
//			cerr << endl;
//		}
	}

	void ExportKey(filesystem::path outputDirPath) {

		string keyHexString = GetSymmetricKeyAsHexString();

		filesystem::path keyFilePath = outputDirPath / GetKeyFileName();

		StringSource in(keyHexString, true, new FileSink(keyFilePath.c_str()));

		cout << "Export Results" << endl;
		cout << "Plain file : " << GetPlainFileName() << endl;
		cout << "Encrypted file : " << GetEncryptedFileName() << endl;
		cout << "Key file : " << keyFilePath << endl;
		cout << "key value : " << keyHexString << endl << endl;
	}

	filesystem::path DecryptFile(filesystem::path encryptedFilePath,
			filesystem::path outputDirPath) {

		byte iv[AES::BLOCKSIZE];
		memset(iv, 0x01, AES::BLOCKSIZE);

		unsigned short ivSize = 0;

		FileSource in(encryptedFilePath.c_str(), false);

		in.Pump(2);
		in.GetWord16(ivSize);

		in.Pump(ivSize);
		in.Get(iv, ivSize);

		CTR_Mode<AES>::Decryption aes_ctr_dec(GetSymmetricKey(), KEYSIZE, iv);
		StreamTransformationFilter *stf = new StreamTransformationFilter(
				aes_ctr_dec);
		in.Attach(stf);

		unsigned short keyTest = 0;
		in.Pump(2);
		stf->GetWord16(keyTest);

		if (keyTest != KEYTEST) {
			cout << "Decryption failed. Check your key value for "
					<< encryptedFilePath.native() << endl;
			exit(EXIT_FAILURE);
		}

		unsigned short plainFileNameSize = 0;
		in.Pump(2);
		stf->GetWord16(plainFileNameSize);

		byte plainFileNameBytes[plainFileNameSize];
		in.Pump(plainFileNameSize);
		stf->Get(plainFileNameBytes, plainFileNameSize);

		plainFileName = string((const char*) plainFileNameBytes);
		filesystem::path resultFilePath = outputDirPath / GetDecryptedFileName();

		stf->Detach(new FileSink(resultFilePath.c_str()));
		in.PumpAll();

		cout << "Decryption Results" << endl;
		cout << "Encrypted file : " << encryptedFilePath.native() << endl;
		cout << "Decrypted file : " << resultFilePath.native() << endl;
		cout << "Original file : " << plainFileName << endl << endl;

		return resultFilePath;
	}

	filesystem::path DecryptAndAuthenticateFile(filesystem::path encryptedFilePath,
			filesystem::path outputDirPath) {

		cout << "ERROR: Decryption with authentication not implemented" << endl;

//		byte iv[AES::BLOCKSIZE];
//		memset(iv, 0x01, AES::BLOCKSIZE);
//
//		unsigned short ivSize = 0;
//
//		FileSource in(encryptedFilePath.c_str(), false);
//
//		// retrieve IV size
//		in.Pump(2);
//		in.GetWord16(ivSize);
//
//		// retrieve IV bytes
//		in.Pump(ivSize);
//		in.Get(iv, ivSize);
//
//		byte adata[ivSize+2];
//		istream is = in.GetStream();
//		is.read((char*)adata, sizeof(adata));
//
//		try
//		{
//		    GCM< AES >::Decryption decryptor;
//		    decryptor.SetKeyWithIV(GetSymmetricKey(), KEYSIZE, iv, sizeof(iv));
//
//
//		    AuthenticatedDecryptionFilter df(decryptor, NULL, AuthenticatedDecryptionFilter::MAC_AT_END, TAGSIZE);
//
//		    df.ChannelPut( AAD_CHANNEL, adata, sizeof(adata));
//
//		    byte bytes[AES::BLOCKSIZE];
//			while (in.MaxRetrievable() > 0) {
//				in.Pump(sizeof(bytes));
//				unsigned short bytesRetrieved = in.Get(bytes, sizeof(bytes));
//				df.ChannelPut(DEFAULT_CHANNEL, bytes, bytesRetrieved);
//			}
//			df.MessageEnd();
//
//		    // If the object does not throw, here's the only
//		    //  opportunity to check the data's integrity
//		    bool verified = df.GetLastResult();
//
//		    if (!verified) {
//		    	cout << "ERROR: input file failed to verify: " << encryptedFilePath.native() << endl << endl;
//		    	exit(EXIT_FAILURE);
//		    }
//
//
//		    // Remove data from channel
//		    string retrieved;
//		    size_t n = (size_t)-1;
//
//		    // Plain text recovered from enc.data()
//		    df.SetRetrievalChannel( DEFAULT_CHANNEL );
//		    n = (size_t)df.MaxRetrievable();
//		    retrieved.resize( n );
//
//		    if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
//		    rpdata = retrieved;
//		    assert( rpdata == pdata );
//
//		    // All is well - work with data
//		    cout << "Decrypted and Verified data. Ready for use." << endl;
//		    cout << endl;
//
//		    cout << "adata length: " << adata.size() << endl;
//		    cout << "pdata length: " << pdata.size() << endl;
//		    cout << endl;
//
//		    cout << "recovered adata length: " << radata.size() << endl;
//		    cout << "recovered pdata length: " << rpdata.size() << endl;
//		    cout << endl;
//		}
//		catch( CryptoPP::Exception& e )
//		{
//		    cerr << "Caught Exception..." << endl;
//		    cerr << e.what() << endl;
//		    cerr << endl;
//		}
//
//
//
//
//
//
//
//
//
//
//		in.Pump(2);
//		in.GetWord16(ivSize);
//
//		in.Pump(ivSize);
//		in.Get(iv, ivSize);
//
//		CTR_Mode<AES>::Decryption aes_ctr_dec(GetSymmetricKey(), KEYSIZE, iv);
//		StreamTransformationFilter *stf = new StreamTransformationFilter(
//				aes_ctr_dec);
//		in.Attach(stf);
//
//		unsigned short keyTest = 0;
//		in.Pump(2);
//		stf->GetWord16(keyTest);
//
//		if (keyTest != KEYTEST) {
//			cout << "Decryption failed. Check your key value for "
//					<< encryptedFilePath.native() << endl;
//			exit(EXIT_FAILURE);
//		}
//
//		unsigned short plainFileNameSize = 0;
//		in.Pump(2);
//		stf->GetWord16(plainFileNameSize);
//
//		byte plainFileNameBytes[plainFileNameSize];
//		in.Pump(plainFileNameSize);
//		stf->Get(plainFileNameBytes, plainFileNameSize);
//
//		plainFileName = string((const char*) plainFileNameBytes);
//		filesystem::path resultFilePath = outputDirPath
//				/ GetDecryptedFileName();
//
//		stf->Detach(new FileSink(resultFilePath.c_str()));
//		in.PumpAll();
//
//		cout << "Decryption Results" << endl;
//		cout << "Encrypted file : " << encryptedFilePath.native() << endl;
//		cout << "Decrypted file : " << resultFilePath.native() << endl;
//		cout << "Original file : " << plainFileName << endl << endl;
//
		return NULL;
	}

	static bool DecryptFile(string keyString,
			filesystem::path encryptedFilePath, filesystem::path outputDirPath, bool authenticate,
			string encryptedFileName = "") {

		byte symmetricKeyBytes[KEYSIZE];

		if ((keyString.length() == 2 * KEYSIZE) && IsHexString(keyString)) {
			HexStringToBytes(keyString, symmetricKeyBytes, KEYSIZE);
			CloudCrypto decryptor(symmetricKeyBytes, encryptedFileName);

			if (authenticate) {
				decryptor.DecryptAndAuthenticateFile(encryptedFilePath, outputDirPath);
			} else
				decryptor.DecryptFile(encryptedFilePath, outputDirPath);

			return true;
		}

		return false;
	}

	static string BytesToHexString(const byte* data,
			const unsigned int dataLength) {

		string out;
		MeterFilter meter(new StringSink(out));
		ArraySource in(data, dataLength, true,
				new HexEncoder(new Redirector(meter), false));

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

	const byte* GetSymmetricKey() const {
		return symmetricKey;
	}

	const string GetSymmetricKeyAsHexString() const {
		string keyHexString;
		return BytesToHexString(symmetricKey, KEYSIZE);
	}

	const string GetPlainFileName() const {
		return plainFileName;
	}

	const string GetEncryptedFileName(bool isSigned = false) {
		return encryptedFileNameBase
				+ (isSigned ?
						encryptedSignedFileExtension : encryptedFileExtension);
	}

	const string GetDecryptedFileName(bool isSigned = false) {

		string decryptedFileName =
				encryptedFileNameBase
						+ (isSigned ?
								decryptedValidatedFileExtension :
								decryptedFileExtension);

		if (!plainFileName.empty())
			decryptedFileName +=
					filesystem::path(plainFileName).extension().native();

		return decryptedFileName;
	}

	const string GetKeyFileName() {
		return encryptedFileNameBase + keyFileExtension;
	}

protected:
	CloudCrypto(byte *symmetricKey, string encryptedFileName) {
		memcpy(this->symmetricKey, symmetricKey, KEYSIZE);

		if (!encryptedFileName.empty()) {
			encryptedFileNameBase = encryptedFileName;

			int dot = encryptedFileName.find('.', 0);
			if (dot != string::npos)
				encryptedFileNameBase = encryptedFileNameBase.substr(0, dot);
		}
	}

	void DeriveSymmetricKey(const string plainFileName,
			const byte *masterKeyBytes, unsigned int masterKeyLength) {

		HMAC<SHA256> hmac(masterKeyBytes, KEYSIZE);
		hmac.CalculateDigest(symmetricKey, (byte*) plainFileName.c_str(),
				plainFileName.size());
	}

	void DeriveEncryptedFileNameBase() {

		byte nameHash[KEYSIZE];

		SHA256 hash;
		hash.CalculateDigest(nameHash, (byte*) plainFileName.c_str(),
				plainFileName.length());

		string nameHashString = BytesToHexString(nameHash, KEYSIZE);

		encryptedFileNameBase = nameHashString.substr(0, 4) + "-"
				+ nameHashString.substr(4, 4) + "-"
				+ nameHashString.substr(nameHashString.size() - 8, 4) + "-"
				+ nameHashString.substr(nameHashString.size() - 4, 4);
	}

};

// globals
string usageMessage = "";
string keyInput = "";
filesystem::path inputFilePath("");
string filenameInput = "";
filesystem::path outputDirPath("");
bool signFlag = false;

map<string, string> parse_arguments(int argc, char **argv) {
	po::options_description options("Cloud crypto commands");
	options.add_options()("help,h", "Cloud crypto options")
			("command", po::value<std::string>(), "cloud crypto command to execute. One of preprocess, authorize, or recover")
			("key,k", po::value<string>(), "Key value as hex string or path to key file containing key as hex string.")
			("inputFile,i", po::value<string>(), "Path to input file")
			("name,n", po::value<string>(), "Alternate name for input file (optional). If omitted, use name of input file.")
			("outputDir,o", po::value<string>(), "Path to output directory (optional). If omitted, reuse input directory.")
			("sign,s", "Sign output for confidentiality with integrity.");

	ostringstream os;
	os << options << endl << endl;
	usageMessage = os.str();

	po::positional_options_description positionals;
	positionals.add("command", 1);

	po::variables_map vm;

	po::parsed_options parsed_options =
			po::command_line_parser(argc, argv).options(options).positional(
					positionals).allow_unregistered().run();

	po::store(parsed_options, vm);

	set<string> valid_commands;
	valid_commands.insert("preprocess");
	valid_commands.insert("authorize");
	valid_commands.insert("recover");

	map<string, string> args;
	if (vm.count("command"))
		args["command"] = vm["command"].as<std::string>();

	if ((args.count("command") == 0) || vm.count("help") || vm.empty()) {
		cout << options << endl;

		exit(EXIT_FAILURE);
	}

	if (vm.count("key"))
		args["key"] = vm["key"].as<string>();

	if (vm.count("inputFile"))
		args["inputFile"] = vm["inputFile"].as<string>();

	if (vm.count("name"))
		args["name"] = vm["name"].as<string>();

	if (vm.count("outputDir"))
		args["outputDir"] = vm["outputDir"].as<string>();

	if (vm.count("sign"))
		args["sign"] = "true";

	return args;
}

/**
 * Validate arguments for the preprocess command. Key and inputFile are required.
 * Optional values for name and outputDir can be derived.
 */
bool ValidatePreprocessArguments(map<string, string> args) {
	if (!(args.count("key") && args.count("inputFile"))) {
		cout << "ERROR: Key and input file are required arguments to 'preprocess'" << endl << endl;
		return false;
	}

	// interpret key as string value or path to file and load contents as string
	// string value may be key bytes as hex string or passphrase to be expanded into key
	filesystem::path keyPath(args["key"]);
	if (filesystem::exists(keyPath)) {
		FileSource in(keyPath.c_str(), true, new StringSink(keyInput));
	} else
		keyInput = args["key"];

	// interpret inputFile as path to file
	filesystem::path inputPath(args["inputFile"]);
	if (filesystem::exists(inputPath) && filesystem::is_regular_file(inputPath))
		inputFilePath = inputPath;
	else {
		cout << "ERROR: Input file not found: " << inputPath.native() << endl << endl;
		return false;
	}

	// interpret name (optional)
	if (args.count("name")) {
		filesystem::path namePath(args["name"]);
		if (filesystem::exists(namePath))
			FileSource in(namePath.c_str(), true, new StringSink(filenameInput));
		else
			filenameInput = args["name"];
	} else
		// use the name from the input file
		// inputFile is required so we know this exists
		filenameInput = inputFilePath.filename().native();

	// interpret outputDir as path to directory
	filesystem::path outputPath(args["outputDir"]);
	if (filesystem::exists(outputPath) && filesystem::is_directory(outputPath))
		outputDirPath = outputPath;
	else
		// use directory of input file as output directory
		outputDirPath = inputFilePath.parent_path();

	if (args.count("sign"))
		signFlag = true;

	return true;
}

/**
 * Validate arguments for the authorize command. Key and (name or inputFile) are required.
 * Optional value for outputDir can be derived. Without outputDir, this defaults to
 * inputFile parent. If this is not provided, default to current working directory.
 */
bool ValidateAuthorizeArguments(map<string, string> args) {
	if (!(args.count("key") && (args.count("name") || args.count("inputFile")))) {
		cout << "ERROR: Key and input file or input file name are required arguments to 'authorize'" << endl << endl;
		return false;
	}

	// interpret key as string value or path to file and load contents as string
	// string value may be key bytes as hex string or passphrase to be expanded into key
	filesystem::path keyPath(args["key"]);
	if (filesystem::exists(keyPath)) {
		FileSource in(keyPath.c_str(), true, new StringSink(keyInput));
	} else
		keyInput = args["key"];

	// interpret inputFile as path to file
	filesystem::path inputPath(args["inputFile"]);
	if (filesystem::exists(inputPath) && filesystem::is_regular_file(inputPath))
		inputFilePath = inputPath;

	// interpret name (required if inputFile not specified)
	if (args.count("name")) {
		// attempt to process as path to file containing name only
		filesystem::path namePath(args["name"]);
		if (filesystem::exists(namePath))
			FileSource in(namePath.c_str(), true, new StringSink(filenameInput));
		else {
			// no file, just use the string as the name
			filenameInput = args["name"];
		}
	} else if (!inputFilePath.empty())
		// name arg not used, use name of input file, if provided
		filenameInput = inputFilePath.filename().native();
	else {
		// no resource for name (which is required). fail out.
		cout << "ERROR: Unable to determine name for encrypted file." << endl << endl;
		return false;
	}

	// interpret outputDir as path to directory
	filesystem::path outputPath(args["outputDir"]);
	if (filesystem::exists(outputPath) && filesystem::is_directory(outputPath))
		outputDirPath = outputPath;
	else if (!inputFilePath.empty())
		// use directory of input file as output directory
		outputDirPath = inputFilePath.parent_path();
	else
		outputDirPath = filesystem::current_path();

	if (args.count("sign"))
		signFlag = true;

	return true;
}

/**
 * Validate arguments for the recover command. Key and inputFile are required.
 * Optional value for outputDir can be derived. Without outputDir, this defaults to
 * inputFile parent. If this is not provided, default to current working directory.
 */
bool ValidateRecoverArguments(map<string, string> args) {
	if (!(args.count("key") && args.count("inputFile"))) {
		cout << "ERROR: Key and input file are required arguments to 'recover'" << endl << endl;
		return false;
	}

	// interpret key as string value or path to file and load contents as string
	// string value must be key bytes as hex string
	filesystem::path keyPath(args["key"]);
	if (filesystem::exists(keyPath)) {
		FileSource in(keyPath.c_str(), true, new StringSink(keyInput));
	} else
		keyInput = args["key"];

	// for this command, key must be bytes as a hex string
	if (!CloudCrypto::IsHexString(keyInput)) {
		cout << "ERROR: Key value provided was not parseable as 32 bytes in hex representation." << endl << endl;
		return false;
	}

	// interpret inputFile as path to file
	filesystem::path inputPath(args["inputFile"]);
	if (filesystem::exists(inputPath) && filesystem::is_regular_file(inputPath))
		inputFilePath = inputPath;
	else {
		cout << "ERROR: Input file not found: " << inputPath.native() << endl << endl;
		return false;
	}

	// interpret name - serves no purpose since name is in encrypted data
	if (args.count("name")) {
		// attempt to process as path to file containing name only
		filesystem::path namePath(args["name"]);
		if (filesystem::exists(namePath))
			FileSource in(namePath.c_str(), true, new StringSink(filenameInput));
		else
			filenameInput = args["name"];
	} else if (!inputFilePath.empty())
		filenameInput = inputFilePath.filename().native();
	else {
		cout << "ERROR: Unable to set name of encrypted file" << endl << endl;
		return false;
	}

	// interpret outputDir as path to directory
	filesystem::path outputPath(args["outputDir"]);
	if (filesystem::exists(outputPath) && filesystem::is_directory(outputPath))
		outputDirPath = outputPath;
	else if (!inputFilePath.empty())
		// use directory of input file as output directory
		outputDirPath = inputFilePath.parent_path();
	else
		// this case should not occur since inputFile is required
		outputDirPath = filesystem::current_path();

	if (args.count("sign"))
		signFlag = true;

	return true;
}

void Preprocess(map<string, string> args) {

	if (!ValidatePreprocessArguments(args)) {
		cout << usageMessage << endl;
		exit(EXIT_FAILURE);
	}

	CloudCrypto encryptor(filenameInput, keyInput);

	if (signFlag) {
		cout << "ERROR: Encryption with authentication not implemented" << endl;
		//encryptor.EncryptAndSignFile(inputFilePath, outputDirPath);
	} else
		encryptor.EncryptFile(inputFilePath, outputDirPath);
}

void Authorize(map<string, string> args) {
	if (!ValidateAuthorizeArguments(args)) {
		cout << usageMessage << endl;
		exit(EXIT_FAILURE);
	}

	CloudCrypto encryptor(filenameInput, keyInput);
	encryptor.ExportKey(outputDirPath);
}

void Recover(map<string, string> args) {
	if (!ValidateRecoverArguments(args)) {
		cout << usageMessage << endl;
		exit(EXIT_FAILURE);
	}

	CloudCrypto::DecryptFile(keyInput, inputFilePath, outputDirPath, signFlag, filenameInput);
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

	map<string, string> args = parse_arguments(argc, argv);

	if (args["command"] == "preprocess")
		Preprocess(args);
	else if (args["command"] == "authorize")
		Authorize(args);
	else if (args["command"] == "recover")
		Recover(args);
	else
		cout << usageMessage << endl;

}
