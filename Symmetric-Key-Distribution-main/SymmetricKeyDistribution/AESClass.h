#pragma once

#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include <iostream>
#include <string>

using std::string; using std::cout;
using namespace CryptoPP;


class AESClass {
private:
	SecByteBlock key;

	AutoSeededRandomPool prng;
	HexEncoder encoder;
	HexDecoder decoder;
public:
	AESClass() {
		this->key = SecByteBlock(AES::DEFAULT_KEYLENGTH);
		prng.GenerateBlock(key, key.size());
	}
	string getKeyString() {
		string keyString;
		this->encoder.Attach(new StringSink(keyString));
		this->encoder.Put(key, key.size());
		return keyString;
	}

	SecByteBlock getKey() { return this->key;  }
	void regenerateNewKey() {
		prng.GenerateBlock(key, key.size());
	}
	

	void setKey(SecByteBlock newKey) { this->key = newKey; }

	void setKey(string newKey) {
		string decodedKey;
		this->key = SecByteBlock(AES::DEFAULT_KEYLENGTH);
		decoder.Attach(new StringSink(decodedKey));
		decoder.Put((byte*)newKey.data(), newKey.size());
		decoder.MessageEnd();
		this->key = SecByteBlock((const byte*)decodedKey.data(), decodedKey.size());
	}

	bool encryptString(string input, string &result) {
		string ciphered;
		try {
			ECB_Mode<AES>::Encryption e;
			e.SetKey(this->key, this->key.size());
			StringSource s(input, true,
				new StreamTransformationFilter(e, new StringSink(ciphered)));
			result = ciphered;
			return true;
		}
		catch (const Exception& e) {
			return false;
		}
	}
	bool decryptString(string input, string &result) {
		string deciphered;
		try {
			ECB_Mode<AES>::Decryption d;
			d.SetKey(this->key, this->key.size());
			StringSource s(input, true,
				new StreamTransformationFilter(d, new StringSink(deciphered)));
			result = deciphered;
			return true;
		}
		catch (const Exception& e) {
			cout << "Error:" << e.what() << std::endl;
			return false;
		}
	}
};