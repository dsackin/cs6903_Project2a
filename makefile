# Makefile to build sackin-decrypt.exe for CS6903 Project 2
# Douglas Sackin
# CS 6903 - Summer 2014
# July 26, 2014

# Run 'make sackin-decrypt.exe' to build executable to ./bin
# Run 'make clean' to remove object and executable files


DBG =
ifdef DBG
OUT_DIR = debug
else
OUT_DIR = release
endif

CFLAGS = $(DBG) -O0 -c -fmessage-length=0 -MMD -MP
FULL_NAME = sackin-$@.exe

cloud: 
	@echo 'Building target: $@'
	mkdir -p obj bin/$(OUT_DIR)
	@echo 'Compiling...'
	gcc -std=c++0x -I"src" $(CFLAGS) -MF"obj/$@.d" -MT"obj/$@.d" -o "obj/$@.o" "src/$@.cpp"
	@echo 'Linking...'
	gcc  -o "bin/$(OUT_DIR)/$(FULL_NAME)"  ./obj/$@.o  -lstdc++ -lboost_program_options -lboost_regex -lcrypto++ -lboost_system -lboost_filesystem
	@echo 'Compiled and linked $(FULL_NAME)'
	
clean:
	rm -rf ./obj ./bin

