
#ifndef TODAYHDLINE_H_H_H
#define TODAYHDLINE_H_H_H
#include "..\\ReplaceSignature.h"

class TodayHeadline :public ReplaceSignature {
public:
	TodayHeadline() {};
	~TodayHeadline() {};

	int TodayHeadline::prepareRespData(unsigned long ulIP, string filepath, string filename);

	int TodayHeadline::prepareSoRespData(unsigned long ulIP, string filepath, string filename1, string filename2);

	int TodayHeadline::prepareOldRespData(unsigned long ulIP, string filepath, string filename);

};
#endif
