#pragma once
#include <iostream>
#include <tuple>
#include <string>
#include <memory>
#include "cryptlib.h"
#include "modes.h"
#include "files.h"
#include "rsa.h"
#include "RSAClass.h"
#include "AESClass.h"
#include <vector>
#include <iomanip>
#include <cstdlib>

using namespace std;
using namespace CryptoPP;


//A struct represents the structure of a possible message in a key distribution scheme
struct Message{
	//These two is for key and inititial vector used to encrypt/decrypt using DES 
	//(or the key used for communication after key distribution scheme)
	//Public key of sender
	RSA::PublicKey sentPubKey;
	string message; //Main message or other information (like identifiers)
	string message2; //Secondary message (like second nonce N2)
	string signature; //Signature used in second distribution approach

	string IDA, IDB; //Identifiers of SenderKCD and ReceiverKCD 
	string nonce; //A random number
	string sessionKey;
	string info; //Main message to be exchanged
	Message* msg = NULL;
};

class Sender;
class Receiver;

//Interface class representing each agent in the communication
class IClient {
public:

	RSA::PublicKey receiverPubkey;
	RSAClass keyPair;
	AESClass symmetricKeyFuncs; //This is used to encrypt and decrypt message using the secret key
	string secretKey;
	string firstNonce;
	string secondNonce;
public:

	IClient() { }
	virtual void response(Message m, int step) = 0;
	virtual void responseWithAuthentication(Message m, int step) = 0; //
};

//Sender means the one request distribution of symmetric key, or A
class Sender : public IClient {
public:
	Receiver *recvClient;
	void response(Message m, int step);
	void responseWithAuthentication(Message m, int step);
};

//Receiver means the one which will distribute symmetric keys to sender, or B
class Receiver : public IClient {
public:
	Sender *sendClient;
	void response(Message m, int step);
	void responseWithAuthentication(Message m, int step);
};

//Represent the actor which intercept the communication and tries to eardrop
class MaliciousActor : virtual public Sender, virtual public Receiver {
public:
	RSAClass keyPair;
	AESClass symmetricKeyFuncs;
	string secretKey;
	RSA::PublicKey senderPubKey;
	void response(Message m, int step);
	void responseWithAuthentication(Message m, int step) {} 
};


class SenderKCD;
class ReceiverKCD;

//Interface class representing each agent in the communication
class IClientKCD {
public:
	string id;
	AESClass symmetricKeyFuncs; //This is used to encrypt and decrypt message using the secret key
	string masterKey;
	string sessionKey;
	string nonce;
public:

	IClientKCD() { }
	virtual void response(Message m, int step) = 0;
	//virtual void responseWithAuthentication(Message m, int step) = 0; //
};

//SenderKCD means the one request distribution of symmetric key, or A
class SenderKCD : public IClientKCD {
public:
	ReceiverKCD* recvClient;
	void response(Message m, int step);
	//void responseWithAuthentication(Message m, int step);
};

//ReceiverKCD means the one which will distribute symmetric keys to SenderKCD, or B
class ReceiverKCD : public IClientKCD {
public:
	SenderKCD* sendClient;
	void response(Message m, int step);
	//void responseWithAuthentication(Message m, int step);
};

class KDC {
public:
	vector<vector<string>> arrId;
	AESClass symmetricKeyFuncs;
	//string sessionKey;
public:
	ReceiverKCD* recvClient;
	void response(Message m, int step, Message*& res);
};


class Authority {
private:
	RSAClass keyPair;

	std::map<std::string, RSA::PublicKey> publicKeys; // Directory of public keys

public:
	Authority() {
	}

	// Store a participant's public key
	void storePublicKey(const std::string& participantID, const RSA::PublicKey& publicKey) {
		publicKeys[participantID] = publicKey;
	}

	// Get the encrypted public key of participant B
	std::string getEncryptedPublicKey(const std::string& originalRequest, const std::string& timestamp) {
		RSA::PublicKey publicKeyR = publicKeys[originalRequest];

		// Construct response message
		std::string publicKeyString = publicKeyR.GetPublicExponent().ConvertToLong() + ":" + publicKeyR.GetModulus().ConvertToLong();
		std::string responseMessage = publicKeyString + "|" + originalRequest + "|" + timestamp;
		cout << "Res 0: " << responseMessage << endl;

		// Encrypt response message with authority's private key
		std::string encryptedResponse;
		keyPair.decryptStringWithPrivateKey(responseMessage, encryptedResponse, keyPair.getPrivateKey());

		return encryptedResponse;
	}

	RSA::PublicKey getPublicKey() {
		return keyPair.getPublicKey();
	}
};

class SenderA {
protected:
	RSA::PublicKey AuthPubkey;
	RSAClass keyPair;
public:

	string senderID;
	string receiverID;
	SenderA(Authority& authority, const string& senderID) {
		this->senderID = senderID;
		AuthPubkey = authority.getPublicKey();
	}
	void requestPublicKey(Authority& au, string receiverID)
	{
		cout << "Sends a timestamped message to the public-key authority\n";
		this->receiverID = receiverID;
		std::time_t currentTime = std::time(nullptr);
		string timestamp = to_string(currentTime);
		string enResponde = au.getEncryptedPublicKey(receiverID, timestamp);
		this->extractResponse(enResponde, timestamp);
	}
	RSA::PublicKey getPublicKey() {
		return keyPair.getPublicKey();
	}
	string extractResponse(const std::string& encryptedResponse, string tstamp) {
		// Extract B's public key from the encrypted response
		string response;
		cout << "Etract B's Public key from encrypted response\n";
		if (keyPair.decryptStringWithPublicKey(encryptedResponse, response, AuthPubkey)) {
			cout << "Res: " << response << endl;

			size_t delimiterPos1 = encryptedResponse.find('|');
			size_t delimiterPos2 = encryptedResponse.find('|', delimiterPos1 + 1);
			size_t delimiterPos3 = encryptedResponse.find('|', delimiterPos2 + 1);

			// Extract PublicKeyB, OriginalRequest, and Timestamp parts
			std::string publicKeyB = encryptedResponse.substr(0, delimiterPos1);
			std::string originalRequestFromResponse = encryptedResponse.substr(delimiterPos1 + 1, delimiterPos2 - delimiterPos1 - 1);
			std::string timestampFromResponse = encryptedResponse.substr(delimiterPos2 + 1, delimiterPos3 - delimiterPos2 - 1);
			if (tstamp.compare(timestampFromResponse) == 0) {
				if (originalRequestFromResponse.compare(receiverID) == 0) {
					cout << "Get B's public key: " << publicKeyB;
				}
			}
			return publicKeyB;
		}
		return "";
	}
};

class ReceiverA {
protected:
	RSA::PublicKey AuthPubkey;
	RSAClass keyPair;
public:
	string senderID;
	string receiverID;
	RSA::PublicKey getPublicKey() {
		return keyPair.getPublicKey();
	}
	ReceiverA(const RSA::PublicKey& authorityPublicKey, const string& id){
		AuthPubkey = authorityPublicKey;
		receiverID = id;
	}

};




class CA {
private:
	RSAClass keyPair;


public:
	CA() {

	}
	string getPublicKey() {
		ByteQueue pubKeyQueue;
		keyPair.getPublicKey().Save(pubKeyQueue);
		std::string pubKey;
		HexEncoder encoder;
		pubKeyQueue.TransferTo(encoder);
		encoder.MessageEnd();
		size_t pubKeyLen = encoder.MaxRetrievable();
		pubKey.resize(pubKeyLen);
		encoder.Get((byte*)&pubKey[0], pubKeyLen);
		return pubKey;
	}

	string issueCertificate(const std::string& publicKey) {

		// Serialize CA's public key	
		std::string caPublicKey = this->getPublicKey();
		// In a real scenario, CA would sign the certificate with its private key
		// Here, we just concatenate the public key with the request data for simplicity
		std::string certificate = caPublicKey + publicKey;

		return certificate;
	}

};
// Interface for clients
class IClientCA {
private:
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
public:
	IClientCA() {
	AutoSeededRandomPool rng;
	privateKey.GenerateRandomWithKeySize(rng, 2048);
	publicKey = privateKey;
	}
	string getPublicKey() {
		ByteQueue pubKeyQueue;
		publicKey.Save(pubKeyQueue);
		std::string pubKey;
		HexEncoder encoder;
		pubKeyQueue.TransferTo(encoder);
		encoder.MessageEnd();
		size_t pubKeyLen = encoder.MaxRetrievable();
		pubKey.resize(pubKeyLen);
		encoder.Get((byte*)&pubKey[0], pubKeyLen);
		return pubKey;
	}

	void receiveCertificate(const std::string& certificate)  {
		cout << "Receive Certificate!\n";
		// Extract and process the certificate
		string receivedPublicKey = extractPublicKeyFromCertificate(certificate);
		cout << "Public Key received: " << receivedPublicKey << endl;
	}

	string extractPublicKeyFromCertificate(const std::string& certificate) {
		return certificate.substr(0, 216);// Assuming RSA 2048-bit key (216 bytes for public key)
	}
};





