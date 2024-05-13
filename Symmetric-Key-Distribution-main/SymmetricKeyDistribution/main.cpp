// SymmetricKeyDistribution.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include "AESClass.h"
#include "Agent.h"


int main()
{
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

	return 0;
}
