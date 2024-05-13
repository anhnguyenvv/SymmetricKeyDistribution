#include "Agent.h"


void Receiver::response(Message m, int step) {
	if (step == 1) {
		cout << "Identifier of A: " << m.message << endl;
		//B generates a secret key, K_s
		this->symmetricKeyFuncs.regenerateNewKey();

		string key = this->symmetricKeyFuncs.getKeyString();
		string message = key; //Message is the secret key

		//Encrypt the secret key with A's public key
		this->receiverPubkey = m.sentPubKey;
		string encryptedKey; 
		this->keyPair.encryptStringWithPublicKey(key, encryptedKey, this->receiverPubkey);
		Message sendMessage; sendMessage.message = encryptedKey;

		this->sendClient->response(sendMessage, 2);
		
	}
	else if (step == 3) {
		string messageFromA; bool result = this->symmetricKeyFuncs.decryptString(m.message, messageFromA);
		//if (result) {
			cout << "B reads message from A: " << messageFromA << endl;
		//}

		//First sample message with distributed secret key
		Message sendMessage; string message, encryptedMessage;
		message = "Message from B!";

		cout << "Input message from B: ";
		cin >> message;
		this->symmetricKeyFuncs.encryptString(message, encryptedMessage);
		sendMessage.message = encryptedMessage;

		this->sendClient->response(sendMessage, 4);
	}
}

void Sender::response(Message m, int step) {
	
	if (step == 0) {
		//Since Sender's pairKey's class RSAClass generate the keys in the constructor already, no need to do here
		Message message; message.sentPubKey = this->keyPair.getPublicKey();
		message.message = "{ \"email\": \"some_email_here@smtps.test.com\", \"token\": \"sometokenhere\" }"; //Sample identifier

		this->recvClient->response(message, 1);
	}
	else if (step == 2) {
		bool result = this->keyPair.decryptString(m.message, this->secretKey);
		if (result == true) {
			cout << "A has got the secret key: " << this->secretKey << endl;
		}
		else {
			cout << "Decryption failed." << endl;
		}
		this->keyPair.regenerateKeyPair(); //Regenerate new key pair (for other transaction) and drop the old ones


		//Get the symmetric key from B
		string decryptKey = this->secretKey;

		this->symmetricKeyFuncs.setKey(decryptKey);

		//Send sample message encrypted with secret key
		string message;
		cout << "Input message from A: ";
		cin >> message;
		Message sendMessage; this->symmetricKeyFuncs.encryptString(message, sendMessage.message);
		this->recvClient->response(sendMessage, 3);
		
	}
	else if (step == 4) {

		string messageFromReceiver;
		bool result = this->symmetricKeyFuncs.decryptString(m.message, messageFromReceiver);
		if (result) {
			cout << "A reads message from B: " << messageFromReceiver << endl;
		}
	}
}

void MaliciousActor::response(Message m, int step) {
	if (step == 1) {
		cout << "An malicious actor is intercepting the message" << endl;
		Message forgedMessage; //Intercept m from A and create a forged message to B containing the malicious actor's public key
		forgedMessage.sentPubKey = this->keyPair.getPublicKey();
		forgedMessage.message = m.message;
		this->senderPubKey = m.sentPubKey; //A's public key
		this->recvClient->response(forgedMessage, 1);
	}
	else if (step == 2) {
		//Since the malicious actor send to B its public key, now it can use its private key to decrypt the secret key
		string receiverSymmetricKey; //Secret key
		this->keyPair.decryptString(m.message, receiverSymmetricKey); 
		cout << "Ah hah, a malicious actor has got the secret key: " << receiverSymmetricKey << endl;
		this->secretKey = receiverSymmetricKey;
		this->symmetricKeyFuncs.setKey(this->secretKey);

		string encryptedKey;
		this->keyPair.encryptStringWithPublicKey(this->secretKey, encryptedKey, this->senderPubKey);
		Message forgedMessage; forgedMessage.message = encryptedKey;

		cout << "The malicious actor has forged B's message to A." << endl;

		this->sendClient->response(forgedMessage, 2);
	}
	else if (step == 3) {
		string secretMessage;//Use the secret key to decrypt and read to secret message between A and B
		this->symmetricKeyFuncs.decryptString(m.message, secretMessage);
		cout << "The malicious actor read the message from A: "<< secretMessage << endl;
		this->recvClient->response(m, 3);
	}
	else if (step == 4) {
		string secretMessage;//Use the secret key to decrypt and read to secret message between A and B
		this->symmetricKeyFuncs.decryptString(m.message, secretMessage);
		cout << "The malicious actor read the message from B: " << secretMessage << endl;
		this->sendClient->response(m, 4);
	}
}

void Receiver::responseWithAuthentication(Message m, int step) {
	if (step == 1) {
		cout << "B send its public key to A."  << endl;

		//Get A's public key
		this->receiverPubkey = m.sentPubKey;
		
		Message sendMessage; sendMessage.sentPubKey = this->keyPair.publicKey;
		cout << "End exchanging public keys." << endl;
		this->sendClient->responseWithAuthentication(sendMessage, 2);
	
	}
	else if (step == 3) {
		string identifier, decryptedFirstNonce;
		this->keyPair.decryptString(m.message, decryptedFirstNonce);
		this->keyPair.decryptString(m.message2, identifier);

		cout << "B gets identifier of A: " << identifier << endl;

		this->symmetricKeyFuncs.regenerateNewKey(); //Generate N2, for simplicity we generate a new symmetric key
		this->secondNonce = this->symmetricKeyFuncs.getKeyString(); //B get N2, save it for later verification and then send its identifier and N1
		this->symmetricKeyFuncs.regenerateNewKey();

		Message sendMessage;
		string encryptedFirstNonce, encryptedSecondNonce; //Nonces encrypted by A's public key
		this->keyPair.encryptStringWithPublicKey(decryptedFirstNonce, encryptedFirstNonce, this->receiverPubkey);
		this->keyPair.encryptStringWithPublicKey(this->secondNonce, encryptedSecondNonce, this->receiverPubkey);
		sendMessage.message = encryptedFirstNonce; sendMessage.message2 = encryptedSecondNonce;

		this->sendClient->responseWithAuthentication(sendMessage, 4);
	}
	else if (step == 5) {
		string decryptedSecondNonce;
		this->keyPair.decryptString(m.message, decryptedSecondNonce);

		if (this->secondNonce != decryptedSecondNonce) {
			cout << "Second nonce from A isn't the same as saved one. This connection may be compromised, disconnecting..." << endl;
			return;
		}
		else {
			this->symmetricKeyFuncs.regenerateNewKey();
			string symmetricKey = this->firstNonce = this->symmetricKeyFuncs.getKeyString();

			//Sign the symmetric key, since Crypto++ doesn't support encrypt with private key but we can still sign with private key
			string hexSignature;  this->keyPair.signStringWithPrivateKey(symmetricKey, hexSignature, this->keyPair.privateKey); 

			//Encrypt the signature and secret symmetric key with A's public key
			string encryptedSecretKey;
			this->keyPair.encryptStringWithPublicKey(symmetricKey, encryptedSecretKey, this->receiverPubkey);

			Message sendMessage; sendMessage.signature = hexSignature; sendMessage.message = encryptedSecretKey;
			this->sendClient->responseWithAuthentication(sendMessage, 6);

		}
	}
	else if (step == 7) {
		string messageFromA; bool result = this->symmetricKeyFuncs.decryptString(m.message, messageFromA);
		//if (result) {
		cout << "B reads message from A: " << messageFromA << endl;
		//}

		//First sample message with distributed secret key
		Message sendMessage; string message, encryptedMessage;
		message = "Message from B!";
		cout << "Input message from B: ";
		cin >> message;
		this->symmetricKeyFuncs.encryptString(message, encryptedMessage);
		sendMessage.message = encryptedMessage;

		this->sendClient->response(sendMessage, 4);
	}
}

void Sender::responseWithAuthentication(Message m, int step) {
	if (step == 0) {
		//Since Sender's pairKey's class RSAClass generate the keys in the constructor already, no need to do here
		cout << "A and B exchange their public key." << endl;
		cout << "A send its public key to B." << endl;
		Message message; message.sentPubKey = this->keyPair.getPublicKey();

		this->recvClient->responseWithAuthentication(message, 1);
	}
	else if (step == 2) {
		this->receiverPubkey = m.sentPubKey; //Save B's public key

		this->symmetricKeyFuncs.regenerateNewKey(); //Generate N1, for simplicity we generate a new symmetric key
		this->firstNonce = this->symmetricKeyFuncs.getKeyString(); //A get N1, save it for later verification and then send its identifier and N1
		this->symmetricKeyFuncs.regenerateNewKey();

		Message sendMessage; string encryptedFirstNonce, encryptedIdentifier; 

		string identifier = "{ \"email\": \"some_email_here@smtps.test.com\", \"token\": \"sometokenhere\" }"; //Sample identifier

		this->keyPair.encryptStringWithPublicKey(this->firstNonce, encryptedFirstNonce, this->receiverPubkey);
		this->keyPair.encryptStringWithPublicKey(identifier, encryptedIdentifier, this->receiverPubkey);
		sendMessage.message = encryptedFirstNonce; sendMessage.message2 = encryptedIdentifier;

		this->recvClient->responseWithAuthentication(sendMessage, 3);

	}
	else if (step == 4) {
		string decryptedFirstNonce, decryptedSecondNonce;
		this->keyPair.decryptString(m.message, decryptedFirstNonce); 
		this->keyPair.decryptString(m.message2, decryptedSecondNonce);

		if (this->firstNonce != decryptedFirstNonce) {
			cout << "First nonce from B isn't the same as saved one. This connection may be compromised, disconnecting..." << endl;
			return;
		}
		else {
			Message sendMessage; string encryptedSecondNonce;
			this->keyPair.encryptStringWithPublicKey(decryptedSecondNonce, encryptedSecondNonce, this->receiverPubkey);
			sendMessage.message = encryptedSecondNonce;
			this->recvClient->responseWithAuthentication(sendMessage, 5);
		}
	}
	else if (step == 6) {
		string decryptedSymmetricKey;
		//Since crypto++ for some reason doesn't encrypt hex encoded string with AES, so I left the signature unencrypted
		// then I sign the secret key first, and then encrypt the secret key
		this->keyPair.decryptString(m.message, decryptedSymmetricKey);

		cout << "Sent key: " << decryptedSymmetricKey << endl;

		if (this->keyPair.verifyStringWithPublicKey(decryptedSymmetricKey, m.signature, this->receiverPubkey)) {
			//Signature verified
			cout << "Signature is correct, proceed sending message..." << endl;
			this->symmetricKeyFuncs.setKey(decryptedSymmetricKey);
			//Send sample message encrypted with secret key
			string message = "Message from A!";

			cout << "Input message from A: ";
			cin >> message;
			Message sendMessage; this->symmetricKeyFuncs.encryptString(message, sendMessage.message);
			this->recvClient->responseWithAuthentication(sendMessage, 7);
		}
		else {
			cout << "Incorrect signature, the key is either corrupted or compromised, disconnecting..." << endl;
		}
	}
	else if (step == 8) {
		string messageFromReceiver;
		bool result = this->symmetricKeyFuncs.decryptString(m.message, messageFromReceiver);
		if (result) {
			cout << "A reads message from B: " << messageFromReceiver << endl;
		}
	}
}


void SenderKCD::response(Message m, int step) {
	if (step == 2) {
		if (m.IDA == this->id && m.IDB == this->recvClient->id)
		{
			cout << "\n---- A knows that message originated at the KDC" << endl;
			cout << "Identifier of A: " << m.IDA << endl;
			cout << "Identifier of B: " << m.IDB << endl;
			//cout << "Nonce: " << m.nonce << endl;

			this->symmetricKeyFuncs.setKey(this->masterKey);

			this->symmetricKeyFuncs.decryptString(m.sessionKey, this->sessionKey);
			this->symmetricKeyFuncs.decryptString(m.IDB, this->recvClient->id);
		}

		cout << "\n---- A forwards to B the information that originated at the KDC for B" << endl;
		Message sendMessage = *m.msg;
		this->recvClient->response(sendMessage, 3);
	}
	else if (step == 4) {
		this->symmetricKeyFuncs.setKey(this->sessionKey);

		Message message;
		this->symmetricKeyFuncs.decryptString(m.nonce, message.nonce);
		message.nonce[0] += 1;// = 1;
		this->symmetricKeyFuncs.encryptString(message.nonce, message.nonce);

		message.info = "This is message encrypted by A";
		this->symmetricKeyFuncs.encryptString(message.info, message.info);
		this->recvClient->sessionKey = this->sessionKey;
		this->recvClient->response(message, 5);
	}

	else if (step == 6) {
		this->symmetricKeyFuncs.setKey(this->sessionKey);
		bool result = this->symmetricKeyFuncs.decryptString(m.info, m.info);
		if (result == true) {
			cout << "\n---- A has got the message: " << m.info << endl;
		}
		else {
			cout << "\n---- Decryption failed." << endl;
		}
	}
}

void ReceiverKCD::response(Message m, int step) {
	//this->sendClient = new SenderKCD;

	if (step == 3) {
		this->symmetricKeyFuncs.setKey(this->masterKey);
		this->symmetricKeyFuncs.decryptString(m.sessionKey, this->sessionKey);
		string tmp;
		this->symmetricKeyFuncs.decryptString(m.IDA, tmp);

		if (tmp == this->sendClient->id)
		{
			cout << "\n---- B confirm that the sender is A, due to A's identity" << endl;
			cout << "B creates a new nonce - N2, sends it to A" << endl;
			Message message;
			this->symmetricKeyFuncs.regenerateNewKey();
			message.nonce = this->symmetricKeyFuncs.getKeyString();
			this->nonce = message.nonce;
			cout << "Nonce N2: " << this->nonce << endl;

			this->symmetricKeyFuncs.setKey(this->sessionKey);
			this->symmetricKeyFuncs.encryptString(message.nonce, message.nonce);

			this->sendClient->sessionKey = this->sessionKey;
			this->sendClient->response(message, 4);
		}
		else {
			cout << "\n---- B confirm that the sender is not A, fail!" << endl;

		}
	}
	else if (step == 5) {
		this->symmetricKeyFuncs.setKey(this->sessionKey);

		string tmp;
		this->symmetricKeyFuncs.decryptString(m.nonce, tmp);
		cout << "\n---- Nonce after decryption: " << hex << tmp << endl;

		bool result = this->symmetricKeyFuncs.decryptString(m.info, m.info);
		(int)this->nonce[0] ++;
		if (result == true && tmp == this->nonce)
		{
			cout << "B has got the message: " << m.info << endl;
		}
		else {
			cout << "\n---- Decryption failed." << endl;
		}

		//Send sample message encrypted with session key
		Message message;
		message.info = "\n---- Message from B!";
		this->symmetricKeyFuncs.encryptString(message.info, message.info);
		this->sendClient->sessionKey = this->sessionKey;
		this->sendClient->response(message, 6);

	}
}

void KDC::response(Message m, int step, Message*& res) {
	if (step == 1) {
		string masterKeyA, masterKeyB;
		for (int i = 0; i < this->arrId.size(); i++)
		{
			if (m.IDA == this->arrId[i][0])
				masterKeyA = this->arrId[i][1];
			if (m.IDB == this->arrId[i][0])
				masterKeyB = this->arrId[i][1];
		}

		this->symmetricKeyFuncs.regenerateNewKey();
		string Ks = this->symmetricKeyFuncs.getKeyString();
		cout << "Session key: " << Ks << endl;


		//The message includes two items intended for A encrypted by the master key of A
		this->symmetricKeyFuncs.setKey(masterKeyA);
		this->symmetricKeyFuncs.encryptString(Ks, res->sessionKey);
		this->symmetricKeyFuncs.encryptString(m.IDA, res->IDA);
		this->symmetricKeyFuncs.encryptString(m.IDB, res->IDB);
		this->symmetricKeyFuncs.encryptString(m.nonce, res->nonce);

		res->msg = new Message;

		//The message includes two items intended for B encrypted by the master key of B
		this->symmetricKeyFuncs.setKey(masterKeyB);
		this->symmetricKeyFuncs.encryptString(Ks, res->msg->sessionKey);
		this->symmetricKeyFuncs.encryptString(m.IDA, res->msg->IDA);

	}
}

