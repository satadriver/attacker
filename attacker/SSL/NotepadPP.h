#pragma once
#include "sslPublic.h"
#include <iostream>

using namespace std;

class NotepadPP {
public:
	static int isNotepadPP(string url, string host);
	static int replyNotepadPP(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);

	static int isNotepadExe(string url, string host);
	static int replyNotepadExe(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM http);
};