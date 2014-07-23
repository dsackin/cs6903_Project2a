/*
 * preprocess.cpp
 *
 *  Created on: Jul 19, 2014
 *      Author: doug
 */

#include <iostream>
#include <string>
#include <set>
#include <map>
using namespace std;

#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/program_options.hpp>
using namespace boost;
namespace po = boost::program_options;


#include <crypto++/hex.h>
#include <crypto++/files.h>
#include <crypto++/mqueue.h>
using namespace CryptoPP;

#include "common.h"

#include "CloudEncryptor.hpp"
#include "CloudDecryptor.hpp"


pair<string, map<string, string> > parse_command(int argc, char **argv) {
	po::options_description options("Cloud crypto commands");
	options.add_options()
		("help,h", "Cloud crypto options")
	    ("command", po::value<std::string>(), "cloud crypto command to execute. One of preprocess, authorize, or recover")
	    ("subargs", po::value<std::vector<std::string> >(), "Arguments to cloud crypto command");

	po::positional_options_description positionals;
	positionals.add("command", 1).
	    add("subargs", -1);

	po::options_description subcommand_options("Subcommand options");
	subcommand_options.add_options()
		("key,k", po::value<string>(), "Key value as hex string or path to key file containing key as hex string.")
		("input,i", po::value<string>(), "Path to input file")
		("name,n", po::value<string>(), "Alternate name for input file (optional). If omitted, use name of input file.")
		("output,o", po::value<string>(), "Path to output directory (optional). If omitted, reuse input directory.");

	po::variables_map vm;

	po::parsed_options parsed_options = po::command_line_parser(argc, argv).
	    options(options).
	    positional(positionals).
	    allow_unregistered().
	    run();

	po::store(parsed_options, vm);

	set<string> valid_commands;
	valid_commands.insert("preprocess");
	valid_commands.insert("authorize");
	valid_commands.insert("recover");


	std::string cmd = vm["command"].as<std::string>();

	if ((valid_commands.count(cmd) == 0) || vm.count("help")) {
		cout << options << endl;
		cout << subcommand_options << endl;

		exit(EXIT_FAILURE);
	}


	// Collect all the unrecognized options from the first pass. This will include the
	// (positional) command name, so we need to erase that.
	std::vector<std::string> subcommand_args = po::collect_unrecognized(parsed_options.options, po::include_positional);
	subcommand_args.erase(subcommand_args.begin());

	// Parse again...
	po::store(po::command_line_parser(subcommand_args).options(subcommand_options).run(), vm);


	cout << "command was set to " << cmd << endl;
	map<string, string> args;

	if (vm.count("key")) {
		args["key"] = vm["key"].as<string>();
		cout << "key was set to " << vm["key"].as<string>() << endl;
	}

	if (vm.count("input")) {
		args["input"] = vm["input"].as<string>();
		cout << "input was set to " << vm["input"].as<string>() << endl;
	}

	if (vm.count("name")) {
		args["name"] = vm["name"].as<string>();
		cout << "name was set to " << vm["name"].as<string>() << endl;
	}

	if (vm.count("output")) {
		args["output"] = vm["output"].as<string>();
		cout << "output was set to " << vm["output"].as<string>() << endl;
	}


	return pair<string, map<string, string> >(cmd, args);
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

	pair<string, map<string, string> > config = parse_command(argc, argv);

	cout << config.first;




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
