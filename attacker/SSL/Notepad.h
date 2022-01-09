#pragma once

#include "../Public.h"
#include "PluginServer.h"
#include "../HttpUtils.h"
#include "../attack.h"
#include "sslPublic.h"
#include "..\\ReplaceSignature.h"

class NotePad :public ReplaceSignature {

public:
	static int NotePad::isNotepad(const char * url, const char * host);
	static int NotePad::sendRespPacket(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);
};