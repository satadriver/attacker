#include "simpleJson.h"


string SimpleJson::getBaseValue(string data,string k) {
	string key = "\"" + k + "\"";

	string value = "";
	int pos = data.find(key,0);
	if (pos >= 0)
	{
		pos += key.length();

		pos = data.find(":", pos);
		if (pos >= 0)
		{
			pos++;
			int endpos = data.find(",",pos);
			if (endpos == -1)
			{
				endpos = data.find("}", pos);
				if (endpos == -1)
				{
					endpos = data.find(" ", pos);
					if (endpos == -1)
					{
						return "";
					}
				}
			}

			value = data.substr(pos, endpos - pos);

			while (1)
			{
				int p = value.find(" ");
				if (p >= 0)
				{
					value = value.replace(p, 1, "");
				}
				else {
					break;
				}
			}
		}
	}

	return value;
}

string SimpleJson::getStrValue(string data,string k) {
	string key = "\"" + k + "\"";

	string value = "";
	int pos = data.find(key, 0);
	if (pos >= 0)
	{
		pos += key.length();

		pos = data.find(":", pos);
		if (pos >= 0)
		{
			pos++;

			pos = data.find("\"", pos);
			if (pos >= 0)
			{
				pos++;

				int endpos = data.find("\"", pos);
				if (endpos>=0)
				{
					value = data.substr(pos, endpos - pos);

					while (1)
					{
						int p = value.find(" ");
						if (p >= 0)
						{
							value = value.replace(p, 1, "");
						}
						else {
							break;
						}
					}
				}
			}

		}
	}

	return value;
}