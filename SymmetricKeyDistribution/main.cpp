

// SymmetricKeyDistribution.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include "AESClass.h"
#include "RSAClass.h"
#include "Agent.h"

//#include <openssl/rsa.h>
//#include <openssl/pem.h>

int main()
{
	cout << "\t\t\t\t" << "------------------------------------------------------------------------" << endl;
	cout << "\t\t\t\t" << "                                 CHUC NANG                              " << endl;
	cout << "\t\t\t\t" << "________________________________________________________________________\n" << endl;
	cout << "\t\t\t\t" << "     1.     SYMMETRIC KEY DISTRIBUTION USING SYMMETRIC ENCRYPTION                               \n" << endl;
	cout << "\t\t\t\t" << "     2.     SYMMETRIC KEY DISTRIBUTION USING ASYMMETRIC ENCRYPTION\n" << endl;
	//cout << "\t\t\t\t" << "     3.         Distribution of Public key                                      \n" << endl;
	cout << "\t\t\t\t" << "     0.     Exit.\n" << endl;
	cout << "\t\t\t\t" << "------------------------------------------------------------------------" << endl;
	while (true)
	{
		int chon = 0;
		cout << "Your choosse: ";
		cin >> chon;
		switch (chon) {
		case 1: {
			cout << "\n\n-------------------------------------------------------------------------------\n\n";
			cout << "---- A and B exchange master key with KDC\n";
			SenderKCD* s = new SenderKCD(); ReceiverKCD* r = new ReceiverKCD(); KDC* kdc = new KDC;
			s->recvClient = r; r->sendClient = s;
			s->id = "This is A";
			s->symmetricKeyFuncs.regenerateNewKey();
			//s->symmetricKeyFuncs.setKey(s->masterKey);
			s->masterKey = s->symmetricKeyFuncs.getKeyString();

			r->id = "This is B";
			r->symmetricKeyFuncs.regenerateNewKey();
			//r->symmetricKeyFuncs.setKey(r->masterKey);
			r->masterKey = r->symmetricKeyFuncs.getKeyString();
			//r->sendClient->id = s->id;

			//KDC kdc;
			kdc->arrId.push_back({ s->id, s->masterKey });
			kdc->arrId.push_back({ r->id, r->masterKey });

			cout << setw(20) << left << "Identifier" << setw(30) << left << "Master Key" << endl;

			for (int i = 0; i < kdc->arrId.size(); i++)
			{
				cout << setw(20) << left << kdc->arrId[i][0] << setw(30) << left << kdc->arrId[i][1] << endl;
			}
			//s->recvClient
			cout << "\n---- A issues a request to the KDC for a session key\n";
			Message m;
			kdc->symmetricKeyFuncs.regenerateNewKey();
			m.nonce = kdc->symmetricKeyFuncs.getKeyString();
			s->nonce = m.nonce;

			m.IDA = s->id;
			m.IDB = r->id;

			Message* msgFromKDC = new Message;
			kdc->response(m, 1, msgFromKDC);
			s->response(*msgFromKDC, 2);

			delete s; delete r; delete kdc;
			break;
		}
		case 2: {
			cout << "Scenario of A and B using simple key distribution scheme.\n";

			Sender* s = new Sender(); Receiver* r = new Receiver();
			s->recvClient = r; r->sendClient = s;
			Message m;
			s->response(m, 0);

			cout << "\n\n-------------------------------------------------------------------------------\n\n";
			cout << "Scenario of malicious actor intercepting A and B using simple key distribution scheme.\n";

			MaliciousActor* a = new MaliciousActor();
			s->recvClient = a; a->recvClient = r; //Intercept between A -> B: A -> M -> B
			r->sendClient = a; a->sendClient = s; //Intercept between B -> A: B -> M -> A
			s->response(m, 0);

			cout << "\n\n-------------------------------------------------------------------------------\n\n";
			cout << "Scenario A and B using key distribution scheme with authentication.\n";
			s->recvClient = r; r->sendClient = s;
			s->responseWithAuthentication(m, 0);

			delete s; delete r; delete a;
			break;
		}
		case 3:{
			Authority authority;
			RSA::PublicKey authorityPublicKey = authority.getPublicKey();

			SenderA s(authority, "A'Id");
			ReceiverA r(authorityPublicKey, "B'Id");
			authority.storePublicKey(s.senderID, s.getPublicKey());
			authority.storePublicKey(r.receiverID, r.getPublicKey());

			//erro
			s.requestPublicKey(authority, r.receiverID);


			



			// Create a public key certificate
			break;
		}
		}
		if (chon < 1 || chon > 3)
		{
			break;
		}
	}
	return 0;
}


