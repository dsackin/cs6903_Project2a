/*
 * preprocess.cpp
 *
 *  Created on: Jul 19, 2014
 *      Author: doug
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
using namespace CryptoPP;

#include "common.h"

#include "CloudEncryptor.hpp"
#include "CloudDecryptor.hpp"

// globals
string usageMessage;
string keyInput;
filesystem::path inputFilePath;
string filenameInput;
filesystem::path outputDirPath;

map<string, string> parse_arguments(int argc, char **argv) {
	po::options_description options("Cloud crypto commands");
	options.add_options()("help,h", "Cloud crypto options")("command",
			po::value<std::string>(),
			"cloud crypto command to execute. One of preprocess, authorize, or recover")(
			"key,k", po::value<string>(),
			"Key value as hex string or path to key file containing key as hex string.")(
			"inputFile,i", po::value<string>(), "Path to input file")("name,n",
			po::value<string>(),
			"Alternate name for input file (optional). If omitted, use name of input file.")(
			"outputDir,o", po::value<string>(),
			"Path to output directory (optional). If omitted, reuse input directory.");

	ostringstream os(usageMessage);
	os << options << endl << endl;
	os.flush();

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

	return args;
}


/**
 * Validate arguments for the preprocess command. Key and inputFile are required.
 * Optional values for name and outputDir can be derived.
 */
bool ValidatePreprocessArguments(map<string, string> args) {
	if (!(args.count("key") && args.count("inputFile"))) {
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
	else
		// input file does not exist
		return false;

	// interpret name (optional)
	if (args.count("name"))
		filenameInput = args["name"];
	else
		filenameInput = inputFilePath.filename().native();

	// interpret outputDir as path to directory
	filesystem::path outputPath(args["outputDir"]);
	if (filesystem::exists(outputPath) && filesystem::is_directory(outputPath))
		outputDirPath = outputPath;
	else
		// use directory of input file as output directory
		outputDirPath = inputFilePath.parent_path();

	return true;
}

/**
 * Validate arguments for the authorize command. Key and (name or inputFile) are required.
 * Optional value for outputDir can be derived. Without outputDir, this defaults to
 * inputFile parent. If this is not provided, default to current working directory.
 */
bool ValidateAuthorizeArguments(map<string, string> args) {
	if (!(args.count("key") && (args.count("name") || args.count("inputFile")))) {
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
	if (args.count("name"))
		filenameInput = args["name"];
	else if (NULL != inputFilePath)
		filenameInput = inputFilePath.filename().native();
	else
		return false;

	// interpret outputDir as path to directory
	filesystem::path outputPath(args["outputDir"]);
	if (filesystem::exists(outputPath) && filesystem::is_directory(outputPath))
		outputDirPath = outputPath;
	else if (inputFilePath)
		// use directory of input file as output directory
		outputDirPath = inputFilePath.parent_path();
	else
		outputDirPath = filesystem::current_path();

	return true;
}

/**
 * Validate arguments for the recover command. Key and inputFile are required.
 * Optional value for outputDir can be derived. Without outputDir, this defaults to
 * inputFile parent. If this is not provided, default to current working directory.
 */
bool ValidateRecoverArguments(map<string, string> args) {
	if (!(args.count("key") && args.count("inputFile"))) {
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
	if (!AbstractCloudCrypto::IsHexString(keyInput))
		return false;

	// interpret inputFile as path to file
	filesystem::path inputPath(args["inputFile"]);
	if (filesystem::exists(inputPath) && filesystem::is_regular_file(inputPath))
		inputFilePath = inputPath;

	// interpret name (required if inputFile not specified)
	if (args.count("name"))
		filenameInput = args["name"];
	else if (inputFilePath)
		filenameInput = inputFilePath.filename().native();
	else
		return false;

	// interpret outputDir as path to directory
	filesystem::path outputPath(args["outputDir"]);
	if (filesystem::exists(outputPath) && filesystem::is_directory(outputPath))
		outputDirPath = outputPath;
	else if (inputFilePath)
		// use directory of input file as output directory
		outputDirPath = inputFilePath.parent_path();
	else
		// this case should not occur since inputFile is required
		outputDirPath = filesystem::current_path();

	return true;
}


void Preprocess(map<string, string> args) {

	if (!ValidatePreprocessArguments(args)) {
		cout << usageMessage << endl;
		exit(EXIT_FAILURE);
	}

	CloudEncryptor encryptor(filenameInput, keyInput);
	encryptor.EncryptFile(inputFilePath, outputDirPath);
}

void Authorize(map<string, string> args) {
	if (!ValidateAuthorizeArguments(args)) {
		cout << usageMessage << endl;
		exit(EXIT_FAILURE);
	}

	CloudEncryptor encryptor(filenameInput, keyInput);
	encryptor.ExportKey(outputDirPath);
}

void Recover(map<string, string> args) {
	if (!ValidateRecoverArguments(args)) {
		cout << usageMessage << endl;
		exit(EXIT_FAILURE);
	}

	CloudDecryptor::DecryptFile(keyInput, inputFilePath, outputDirPath);
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

//
//
//	// process command line arguments
//	processArguments(argc, argv, printUsage);
//
//	bool test = isHexString("1234");
//	test = isHexString("abcd");
//	test = isHexString("0");
//	test = isHexString("no1234");
//	test = isHexString("011b");
//	test = isHexString("bd123no");
//
//
//	string b = "a4c321";
//	byte c[b.size()];
//	int bytesProcessed  = AbstractCloudCrypto::HexStringToBytes(b, c, b.size() / 2);
//
//	b = "afdfsd";
//	bytesProcessed = AbstractCloudCrypto::HexStringToBytes(b, c, b.size() / 2);
//	 cout << "hello";
//
////
////	filesystem::path outputPath("/home/doug/projects/cloud2/data");
////
////	filesystem::path in("/home/doug/projects/cloud2/data/test.in");
////
////
////
////
////	CloudEncryptor enc("test.in", "this is my passphrase");
////	enc.EncryptFile2(in);
////
////	filesystem::path keyFilePath = enc.SaveKeyToJsonFile(outputPath);
////
////	cout << keyFilePath.native() << "  " << enc.getSymmetricKeyAsHexString() << endl;
////
////	filesystem::path dataFilePath = outputPath / (enc.getCipherFileNameBase() + enc.getDataFileExtension());
////	CloudDecryptor::DecryptFile(keyFilePath, dataFilePath);
////
//////	CloudDecryptor dec;
//////	dec.InitializeFromKeyFile(keyFilePath);
////
//////	cout << keyFilePath.native() << "  " << dec.getSymmetricKeyAsHexString() << endl;
//
//
}
