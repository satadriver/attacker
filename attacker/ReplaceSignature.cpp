

#include "ReplaceSignature.h"
#include "ReplacePacket.h"
#include "Public.h"
#include "Packet.h"
#include "FileOper.h"
#include "cipher/CryptoUtils.h"




int ReplaceSignature::getField(char * flag,char * end,char * second,const char * lpbuf){
	m_lpfield = strstr((char*)lpbuf,flag);
	if (m_lpfield == FALSE)
	{
		return FALSE;
	}

	m_lpfield += lstrlenA(flag);

	char * lpend = strstr(m_lpfield,end);
	if (lpend == FALSE)
	{
		lpend = strstr(m_lpfield, second);
		if (lpend == FALSE)
		{
			return FALSE;
		}
	}

	m_fieldlen = lpend - m_lpfield;
	return m_fieldlen;
}


int ReplaceSignature::getField(char * flag, char * end, const char * lpbuf) {
	m_lpfield = strstr((char*)lpbuf, flag);
	if (m_lpfield == FALSE)
	{
		return FALSE;
	}

	m_lpfield += lstrlenA(flag);

	char * lpend = strstr(m_lpfield, end);
	if (lpend == FALSE)
	{
		return FALSE;
	}

	m_fieldlen = lpend - m_lpfield;
	return m_fieldlen;
}



int ReplaceSignature::setField(char * flag,char * lpdstbuf){
	char * tmphdr = strstr(lpdstbuf,flag);
	if (tmphdr == FALSE)
	{
		return FALSE;
	}

	tmphdr += lstrlenA(flag);
	memmove(tmphdr, m_lpfield, m_fieldlen);
	return TRUE;
}



int ReplaceSignature::sendRespData(pcap_t * pcapT,const char * lppacket, int packetsize, char * ip,int type,LPPPPOEHEADER pppoe) {

	int ret = 0;
	if (m_iRespSize && m_lpResp )
	{
		ret = AttackPacket::ReplacePacket(pcapT, lppacket, packetsize, m_lpResp, m_iRespSize, ip,type,pppoe);
	}
	return ret;
}




int ReplaceSignature::setRespParams(char * flag, char * end, char *lphttpdata) {

	int flaglen = lstrlenA(flag);
	char srcvalue[256] = { 0 };
	int srcvaluelen = Public::getstring(flag, end, lphttpdata, srcvalue,0);

	char * lphdr = strstr(m_lpResp, flag);
	if (lphdr) {
		lphdr += flaglen;
		char * lpend = strstr(lphdr, end);
		int len = lpend - lphdr;
		if (lpend && len == srcvaluelen)
		{
			memmove(lphdr, srcvalue, len);
			return TRUE;
		}
	}
	return FALSE;
}








