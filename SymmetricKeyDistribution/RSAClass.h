#pragma once
#include "cryptlib.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include "rsa.h"
#include "pssr.h"
#include "filters.h"
#include <iostream>
#include <string>

using std::string; using std::cout;
using namespace CryptoPP;

class RSAClass {
public:
	// Generate keys
	AutoSeededRandomPool rng;
	RSA::PrivateKey privateKey;
	RSA::PublicKey publicKey;
public:
	RSAClass() {
		this->privateKey.GenerateRandomWithKeySize(this->rng, 3072);
		this->publicKey = RSA::PublicKey(this->privateKey);
	}
	void regenerateKeyPair() {
		this->privateKey.GenerateRandomWithKeySize(this->rng, 3072);
		this->publicKey = RSA::PublicKey(this->privateKey);
	}
	RSA::PrivateKey getPrivateKey() {
		return this->privateKey;
	}
	RSA::PublicKey getPublicKey() {
		return this->publicKey;
	}
	bool encryptString(string input, string &result) {
		RSAES_OAEP_SHA_Encryptor e(this->publicKey);
		string ciphered;

		try {
			StringSource ss(input, true,
				new PK_EncryptorFilter(rng, e,
					new StringSink(ciphered)
				) ); 

			result = ciphered;
			return true;
		}
		catch (const Exception &e) {
			return false;
		}	
	}
	bool encryptStringWithPublicKey(string input, string &result, RSA::PublicKey pubKey) {
		RSAES_OAEP_SHA_Encryptor e(pubKey);
		string ciphered;

		try {
			StringSource ss(input, true,
				new PK_EncryptorFilter(rng, e,
					new StringSink(ciphered)
				));

			result = ciphered;
			return true;
		}
		catch (const Exception &e) {
			return false;
		}
	}
	//Error method, since Crypto++ doesn't support encrypt with private key
	/*bool encryptStringWithPrivateKey(string input, string &result, RSA::PrivateKey privKey) {
		RSAES_OAEP_SHA_Encryptor e(privKey);
		string ciphered;

		try {
			StringSource ss(input, true,
				new PK_EncryptorFilter(rng, e,
					new StringSink(ciphered)
				));

			result = ciphered;
			return true;
		}
		catch (const Exception &e) {
			return false;
		}
	}*/
	bool decryptString(string input, string &result) {
		string decrypted;
		RSAES_OAEP_SHA_Decryptor d(this->privateKey);

		try {
			StringSource ss(input, true,
				new PK_DecryptorFilter(rng, d,
					new StringSink(decrypted)
				) );
			result = decrypted;
			return true;
		}
		catch (const Exception &e) {
			return false;
		}
		
	}
	bool decryptStringWithPrivateKey(string input, string &result, RSA::PrivateKey privKey) {
		string decrypted;
		RSAES_OAEP_SHA_Decryptor d(privKey);

		try {
			StringSource ss(input, true,
				new PK_DecryptorFilter(rng, d,
					new StringSink(decrypted)
				));
			result = decrypted;
			return true;
		}
		catch (const Exception &e) {
			return false;
		}

	}

	//Return a hexcoded signature of the input string signed with privKey
	bool signStringWithPrivateKey(string input, string &hexSignature, RSA::PrivateKey privKey) {
		
		try {
			RSASS<PSSR, SHA256>::Signer signer(privKey);
			SecByteBlock signature(signer.MaxSignatureLength());
			size_t signatureLength = signer.SignMessage(rng, reinterpret_cast<const unsigned char*>(input.data()), input.size(), signature);

			//Encoding the signature
			std::string encodedSignature;
			HexEncoder encoder(new StringSink(encodedSignature));
			encoder.Put(signature, signatureLength);
			encoder.MessageEnd();

			hexSignature = encodedSignature;
			return true;

			hexSignature = encodedSignature;
		}catch(const Exception &e){
			return false;
		}
		
	}
	//Verify the string with public key and hex encoded signature
	bool verifyStringWithPublicKey(string message, string hexSignature, RSA::PublicKey pubKey) {
		try {
			RSASS<PSSR, SHA256>::Verifier verifier(pubKey);
			string decodedSignature;
			StringSource ss(hexSignature, true, new HexDecoder(new StringSink(decodedSignature)));
			
			bool isValid = verifier.VerifyMessage((byte*)message.data(), message.length(), (byte*)decodedSignature.data(), decodedSignature.length());
			return isValid;
		}
		catch (const Exception &e) {
			return false;
		}
	}

	//Error method, since Crypto++ doesn't support decrypt with public key
	bool decryptStringWithPublicKey(string input, string &result, RSA::PublicKey pubKey) {
		string decrypted;
		RSAES_OAEP_SHA_Decryptor d(pubKey);

		try {
			StringSource ss(input, true,
				new PK_DecryptorFilter(rng, d,
					new StringSink(decrypted)
				));
			result = decrypted;
			return true;
		}
		catch (const Exception &e) {
			return false;
		}

	}
};