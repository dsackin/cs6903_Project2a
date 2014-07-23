/**
 *  common_main.h
 *
 *
 *  Created on: Jun 18, 2014
 *      Author: Douglas Sackin, NYU CS6903, Summer 2014
 */

#include <getopt.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "prettyprint/prettyprint.hpp"


// Global variables to store the program inputs from wherever they are collected


/**
 * Print a simple message describing the usage of this program
 * @param os - Reference to an output stream to which to write the usage message
 */
void printUsage(std::ostream &os) {
	os << "Usage: decrypt [-d <dictionaryPath>] [-c <cipherPath>] [-t <keyLength>]" << std::endl;
	os << "Attempts to decrypt a cipher text and identify the originating plain text from " << std::endl;
	os << "a dictionary of plain texts. " << std::endl;
	os << std::endl;
	os << std::endl;
	os << "This program requires the dictionary, cipher text, and key length as inputs. " << std::endl;
	os << "You may specify any or none of these on the command line. If no dictionary " << std::endl;
	os << "path is provided, the default dictionary embedded in the program will be " << std::endl;
	os << "assumed. The rest will be collected from stdin." << std::endl;
	os << std::endl;
	os << "-h - print this help message" << std::endl;
	os << "-d <dictionaryPath> - optional path to a text file containing one plain text " << std::endl;
	os << "   candidate per line" << std::endl;
	os << "-c <cipherPath> - optional path to a text file containing a single line of " << std::endl;
	os << "   cipher text for the decryption attempt. If not provided as an argument, " << std::endl;
	os << "   this will be requested via stdin" << std::endl;
	os << "-t <keyLength> - optional integer length of a key phrase believed to be used " << std::endl;
	os << "   in the encryption. If not provided as an argument, this will be requested " << std::endl;
	os << "   via stdin" << std::endl;
	os << std::endl;
}

/**
 * Process arguments passed to the command line of the program. These are passed
 * through directly from main(int argc, char** argv). Parse the options (short
 * options only) using the getopt.h library. Save argument values to global vars
 *
 * @param argc - count of arguments
 * @param argv - array of c-style strings
 */
void processArguments(int argc, char** argv) {
	char c;

	while ((c = getopt(argc, argv, "hd:c:t:")) != -1)
		switch (c) {
		case 'h':									// print help
			printUsage(std::cout);
			abort();
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			break;
		default:
			abort();
		}


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

	// process optional command line arguments
	processArguments(argc, argv);

	std::cout << "hello authorize";
}
