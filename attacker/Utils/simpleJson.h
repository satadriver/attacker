#pragma once

#include <string>

using namespace std;

class SimpleJson {
public:
	static string getBaseValue(string data,string key);
	static string getStrValue(string data,string key);
};