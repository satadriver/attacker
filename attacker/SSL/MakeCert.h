#pragma once



#include <windows.h>
#include <iostream>

using namespace std;

class MakeCert {
public:
	static int MakesureCertExist(string servername);
	static int makeKey(string passpath, string keypath, int bitcnt);

	static int makeCSR(string keyfn, string password, string c, string st, string l, string o, string ou, string cn, string e, string outcsrfn);
	static int makeCRT(string csrfn, string password, string subcakey, string cacertfn, string certfn, string cakeyfn);
	static int makeCRTSelf(string csrfn,string password, string certfn, string cakeyfn);
	//static int makeCACSR(string keyfn, string password, string c, string st, string l, string o, string ou, string cn, string e, string outcsrfn);

	static int makeSuperCACRT(string keyfn,string password,string c,string st, string l,string o,string ou,string cn,string e,string cfgfn,string outcsrfn);

	static int makeSuperCRT(string csrfn, string password, string cacertfn, string certfn, string cakeyfn);

	//static int makeSuperCSR(string keyfn, string password, string c, string st, string l, string o, string ou, string cn, string e, string outcsrfn);

	static int checkCAExist();
	static int makeCA(string cacsrpath, string cacrtpath, string cakeypath);

	static int makeExtCSR(string keyfn,string password,string c,string st,string l,string o,string ou,string cn,string e,string cfgpath,string outcsrfn);
	static int makeExtCRT(string cfgpath, string csrfn, string password, string cacertfn, string certfn, string cakeyfn);

};