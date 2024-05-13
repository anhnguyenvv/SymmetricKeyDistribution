#pragma once
#include <iostream>
#include <tuple>
#include <string>
#include <memory>
#include <vector>
#include <iomanip>
#include <cstdlib> 
#include "cryptlib.h"
#include "modes.h"
#include "files.h"
#include "rsa.h"
#include "AESClass.h"

using namespace std;
using namespace CryptoPP;


//A struct represents the structure of a possible message in a key distribution scheme
struct Message{
	string IDA, IDB; //Identifiers of SenderKCD and ReceiverKCD 
	string nonce; //A random number
	string sessionKey;
	string info; //Main message to be exchanged
	Message* msg = NULL;
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
	ReceiverKCD *recvClient;
	void response(Message m, int step);
	//void responseWithAuthentication(Message m, int step);
};

//ReceiverKCD means the one which will distribute symmetric keys to SenderKCD, or B
class ReceiverKCD : public IClientKCD {
public:
	SenderKCD *sendClient;
	void response(Message m, int step);
	//void responseWithAuthentication(Message m, int step);
};

class KDC{
public:
	vector<vector<string>> arrId;
	AESClass symmetricKeyFuncs;
	//string sessionKey;
public:
	ReceiverKCD* recvClient;
	void response(Message m, int step, Message*& res);
};


//Represent the actor which intercept the communication and tries to eardrop
//class MaliciousActor : virtual public SenderKCD, virtual public ReceiverKCD {
//public:
//	AESClass symmetricKeyFuncs;
//	string secretKey;
//	void response(Message m, int step);
//	void responseWithAuthentication(Message m, int step) {} 
//};

