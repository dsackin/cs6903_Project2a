/**
 * This software is delivered in response to Project 2 for CS6903 in Summer 2014.
 * It is a simple program that encrypts files for sharing with authorized users.
 * One use case is to share the files over cloud file sharing services such as
 * Dropbox and box.net.
 *
 * The encryption scheme uses a common master password or secret key from the
 * sharer and combines this with information from each file to be encrypted
 * to produce a unique symmetric encryption key for each shared file. The
 * sharer then independently delivers this key to the recipients. The
 * recipients use the per-file shared key to decrypt the files while not
 * knowing the common secret key. In addition, the cloud file service provider
 * and eavesdroppers have no knowledge of the file contents or even the file
 * type.
 *
 * The utility uses HMAC<SHA256> to generate the unique 256 bit symmetric key
 * which is used by AES in CTR mode for encryption. SHA256 is also used for key
 * expansion and output file name generation.
 *
 * The utility also includes an implementation to support encryption with
 * authentication/verification. However, this prototype implementation is not
 * functioning due to runtime errors. the implementation uses GCM which is
 * essentially AES with GMAC across encrypted data plus additional data (such
 * as the IV header).
 *
 * The utility compiles to a single executable with three sub-commands. Each
 * sub-command uses a common set of arguments to direct the utility to operate
 * on the files. The utilities each allow a range of freedom in specifying the
 * arguments (as detailed below).
 *
 * Cloud crypto commands:
 *  -h [ --help ]          Cloud crypto options
 *  --command arg          cloud crypto command to execute. One of preprocess,
 *                         authorize, or recover
 *  -k [ --key ] arg       Key value as hex string or path to key file containing
 *                         key as 64 character hex string
 *  -i [ --inputFile ] arg Path to input file
 *  -n [ --name ] arg      Alternate name for input file (optional). If omitted,
 *                         use name of input file.
 *  -o [ --outputDir ] arg Path to output directory (optional). If omitted, use
 *                         input directory.
 *  -s [ --sign ]          Sign output for confidentiality with integrity
 *  					   (work in progress)
 *
 *
 * The following file formats are used in the program:
 *   - plain input files - *.* - input files are in their native format
 *   - encrypted files - *.enc.cld - encrypted files are in binary. To view in
 *   	hex, use the appropriate options in your text editor.
 *   - key files - *.key.cld - text, containing 64 hexadecimal digits
 *   	representing 32 byte values
 *   - decrypted files - *.dec.cld.* - decrypted files are in the original
 *   	format of their plain input
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

/**
 * CloudCrypto is the core class representing the use of a symmetric key to
 * encrypt and decrypt a file.
 *
 * To encrypt a file, construct a CloudCrypto object using the name of the
 * plain file and string containing the master key input. This will generate
 * a unique symmetric key for that file. Then call EncryptFile() to encrypt
 * and save it to a destination directory using a unique generated name.
 *
 * To export the key, construct a CloudCrypto object as above, then
 * immediately call ExportKey() to save off the key for sharing.
 *
 * To decrypt the file, call the static DecryptFile() function. This will
 * construct a CloudCrypto from the key input, then decrypt and save the
 * contents of the input file.
 */
class CloudCrypto {

protected:
	static const unsigned int KEYSIZE = SHA256::DIGESTSIZE;
	static const unsigned int TAGSIZE = 16;

	// used to validate decryption success. Equivalent to 0xAB 0xCD
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

	/**
	 * Construct an instance using a file name and the master key input
	 * as a string. If the key input can be interpreted as a 64 character
	 * hex string, it is converted to 32 bytes of input and used directly
	 * as the data. Otherwise, the string is considered a master password
	 * and is hashed with SHA256 to expand it to 256 bits. Once the master
	 * key has 256 bits of input, a per-file symmetric key is derived using
	 * HMAC<SHA256> of the filename.
	 */
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

	/**
	 * Default destructor
	 */
	~CloudCrypto() {
	}

	/**
	 * Encrypt file using AES in CTR mode with saved symmetric key. Take file
	 * input from plainFilePath and write it to outputDirPath using the
	 * obfuscated file name. The IV is serialized into the file in the clear.
	 * The original file name is also serialized in the encrypted text.
	 */
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

	/**
	 * Encrypt and sign file using GCM with AES with saved symmetric key. Take
	 * file input from plainFilePath and write it to outputDirPath using the
	 * obfuscated file name. The IV is serialized into the file in the clear.
	 * The original file name is also serialized in the encrypted text. All
	 * data is signed while only the name and data are encrypted.
	 *
	 * THIS IS WORK IN PROGRESS
	 *
	 */
	void EncryptAndSignFile(filesystem::path plainFilePath,
			filesystem::path outputDirPath) {

		cerr << "ERROR: Encryption with authentication not implemented" << endl;

		byte iv[AES::BLOCKSIZE];

		AutoSeededRandomPool rng;
//		rng.GenerateBlock(iv, AES::BLOCKSIZE);
		memset(iv, 0x01, sizeof(iv));


		filesystem::path encryptedFilePath = outputDirPath / GetEncryptedFileName(true);

		try {
			GCM<AES>::Encryption gcm_aes_enc;
			gcm_aes_enc.SetKeyWithIV(GetSymmetricKey(), KEYSIZE, iv, sizeof(iv));

			AuthenticatedEncryptionFilter ef(gcm_aes_enc,
					new FileSink(encryptedFilePath.c_str()),
					false,
					TAGSIZE		// tag size
					/* MAC_AT_END */
					); // AuthenticatedEncryptionFilter

			// write the iv to the authenticated but not encrypted channel
			ef.ChannelPut(AAD_CHANNEL, iv, sizeof(iv));
			ef.ChannelMessageEnd(AAD_CHANNEL);

			// Authenticated data *must* be pushed before
			//  Confidential/Authenticated data. Otherwise
			//  we must catch the BadState exception
			ef.ChannelPutWord16(DEFAULT_CHANNEL, KEYTEST);

			string plainFileName = plainFilePath.filename().native();
			unsigned short plainFileNameSize = plainFileName.size() + 1;

			ef.ChannelPutWord16(DEFAULT_CHANNEL, plainFileNameSize);
			ef.ChannelPut(DEFAULT_CHANNEL, (byte*) plainFileName.c_str(),
					plainFileNameSize);

//			MessageQueue queue(AES::BLOCKSIZE);
			byte bytes[AES::BLOCKSIZE];

			FileSource in(plainFilePath.c_str(), false);
			in.Attach(new Redirector(ef));
			in.PumpAll();

//			while (in.AnyRetrievable()) {
//				unsigned short bytesRetrieved = in.Get(bytes, sizeof(bytes));
//				ef.ChannelPut(DEFAULT_CHANNEL, bytes, bytesRetrieved);
//			}
			ef.ChannelMessageEnd(DEFAULT_CHANNEL);

			cout << "Encryption Results" << endl;
			cout << "Plain file : " << plainFilePath.native() << endl;
			cout << "Encrypted and Signed file : " << encryptedFilePath.native() << endl;

		} catch (CryptoPP::Exception& e) {
		    cerr << "ERROR: Unable to encrypt and sign: " << plainFilePath << endl;
		    cerr << e.what() << endl << endl;
		}
	}

	/**
	 * Export the unique symmetric key for a file. Keys are written to the
	 * output directory as a text file of 64 hex characters (representing 32
	 * bytes). They are also written to stdout. Either is acceptable input for
	 * decrypting a file.
	 */
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

	/**
	 * Decrypt a file using the symmetric key stored in this CloudCrypto object.
	 * Take the file at the encrypted file path and attempt to decrypt it
	 * using the saved symmetric key. Read the IV from the file, then use this
	 * to decrypt the data. The data has a test value and then the file name
	 * length and value prepended. Write the contents to the output directory.
	 * If the file cannot be decrypted (usually the wrong key), report and exit.
	 */
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

	/**
	 * Decrypt and verify a file using the symmetric key stored in this
	 * CloudCrypto object. Take the file at the encrypted file path and
	 * attempt to decrypt and verify it using the saved symmetric key.
	 * Write the contents to the output directory. If the file cannot be
	 * verified or decrypted (usually the wrong key), report and exit.
	 *
	 * THIS IS WORK IN PROGRES
	 *
	 */
	filesystem::path DecryptAndAuthenticateFile(filesystem::path encryptedFilePath,
			filesystem::path outputDirPath) {

		cerr << "ERROR: Decryption with authentication not implemented" << endl;

		byte iv[AES::BLOCKSIZE];
		memset(iv, 0x01, AES::BLOCKSIZE);

		unsigned short ivSize = 0;

		FileSource in(encryptedFilePath.c_str(), false);

		// retrieve IV size
		in.Pump(2);
		in.GetWord16(ivSize);

		// retrieve IV bytes
		in.Pump(ivSize);
		in.Get(iv, ivSize);

		byte unencrypted[ivSize+2];
		istream *is = in.GetStream();
		is->read((char*)unencrypted, sizeof(unencrypted));

		try
		{
		    GCM< AES >::Decryption decryptor;
		    decryptor.SetKeyWithIV(GetSymmetricKey(), KEYSIZE, iv, sizeof(iv));


		    AuthenticatedDecryptionFilter df(decryptor, NULL, AuthenticatedDecryptionFilter::MAC_AT_END, TAGSIZE);

		    df.ChannelPut( AAD_CHANNEL, unencrypted, sizeof(unencrypted));

		    in.Attach(new Redirector(df));
		    in.PumpAll();

//		    byte bytes[AES::BLOCKSIZE];
//			while (in.MaxRetrievable() > 0) {
//				in.Pump(sizeof(bytes));
//				unsigned short bytesRetrieved = in.Get(bytes, sizeof(bytes));
//				df.ChannelPut(DEFAULT_CHANNEL, bytes, bytesRetrieved);
//			}
			df.MessageEnd();

		    // If the object does not throw, here's the only
		    //  opportunity to check the data's integrity
		    bool verified = df.GetLastResult();

		    if (!verified) {
		    	cerr << "ERROR: input file failed to verify: " << encryptedFilePath.native() << endl << endl;
		    	exit(EXIT_FAILURE);
		    }

		    df.SetRetrievalChannel(DEFAULT_CHANNEL);

			unsigned short keyTest = 0;
			df.GetWord16(keyTest);

			if (keyTest != KEYTEST) {
				cout << "Decryption failed. Check your key value for "
						<< encryptedFilePath.native() << endl;
				exit(EXIT_FAILURE);
			}

			unsigned short plainFileNameSize = 0;
			df.GetWord16(plainFileNameSize);

			byte plainFileNameBytes[plainFileNameSize];
			df.Get(plainFileNameBytes, plainFileNameSize);

			plainFileName = string((const char*) plainFileNameBytes);
			filesystem::path resultFilePath = outputDirPath / GetDecryptedFileName();

			df.Detach(new FileSink(resultFilePath.c_str()));

			cout << "Decryption Results" << endl;
			cout << "Encrypted file : " << encryptedFilePath.native() << endl;
			cout << "Decrypted file : " << resultFilePath.native() << endl;
			cout << "Original file : " << plainFileName << endl << endl;

			return resultFilePath;
		}
		catch( CryptoPP::Exception& e )
		{
		    cerr << "ERROR: Unable to decrypt and verify: " << encryptedFilePath << endl;
		    cerr << e.what() << endl << endl;
		}
	}

	/**
	 * Static method to construct a CloudCrypto object using the provided key
	 * input, then proceed with decryption by called the CloudCrypto object's
	 * DecryptFile method.
	 */
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

	/**
	 * Use HMAC<SHA256> to derive the symmetric key from the master key and
	 * the specified input file name
	 */
	void DeriveSymmetricKey(const string plainFileName,
			const byte *masterKeyBytes, unsigned int masterKeyLength) {

		HMAC<SHA256> hmac(masterKeyBytes, KEYSIZE);
		hmac.CalculateDigest(symmetricKey, (byte*) plainFileName.c_str(),
				plainFileName.size());
	}

	/**
	 * Derive an obfuscated output name from the hash of the specified
	 * input file name.
	 */
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
		cerr << "ERROR: Key and input file are required arguments to 'preprocess'" << endl << endl;
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
		cerr << "ERROR: Input file not found: " << inputPath.native() << endl << endl;
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
		cerr << "ERROR: Key and input file or input file name are required arguments to 'authorize'" << endl << endl;
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
		cerr << "ERROR: Unable to determine name for encrypted file." << endl << endl;
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
		cerr << "ERROR: Key and input file are required arguments to 'recover'" << endl << endl;
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
		cerr << "ERROR: Key value provided was not parseable as 32 bytes in hex representation." << endl << endl;
		return false;
	}

	// interpret inputFile as path to file
	filesystem::path inputPath(args["inputFile"]);
	if (filesystem::exists(inputPath) && filesystem::is_regular_file(inputPath))
		inputFilePath = inputPath;
	else {
		cerr << "ERROR: Input file not found: " << inputPath.native() << endl << endl;
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
		cerr << "ERROR: Unable to set name of encrypted file" << endl << endl;
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
		cerr << "ERROR: Encryption with authentication not implemented" << endl;
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
 * Main program to execute the cloud crypto functionality
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
