#include "Agent.h"

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
		message.nonce[0]+=1;// = 1;
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
