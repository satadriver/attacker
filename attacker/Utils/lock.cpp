#include "lock.h"
#include "../Public.h"
#include "../Utils/Tools.h"

#define SLEEP_ONETIME 20



int Lock::initlock(TOOLSLOCK & lock, const char * name, int timelimit) {
	lstrcpyA(lock.name, name);
	lock.flag = FALSE;
	lock.id = 0;
	lock.timelimit = timelimit;
	return lock.flag;
}

volatile int Lock::enterlock(TOOLSLOCK & lock, ULONGLONG id) {
	int cnt = 0;

	while (1)
	{
		if (lock.flag)
		{
			Sleep(SLEEP_ONETIME);
			cnt += SLEEP_ONETIME;
			if (cnt > lock.timelimit)
			{
				lock.flag = TRUE;
				lock.id = id;

				log( "waiting for lock:%s id:%I64u too long time,force to break\r\n", lock.name, lock.id);
				break;
			}
		}
		else {
			lock.flag = TRUE;
			lock.id = id;
			break;
		}
	}

	return lock.flag;
}

volatile int Lock::leavelock(TOOLSLOCK & lock, ULONGLONG id) {
	if (lock.flag == TRUE && id == lock.id)
	{
		lock.id = 0;
		lock.flag = FALSE;
		return lock.flag;	
	}

	log( "leavelock:%s,id:%I64u,last id:%I64u,value:%u error\r\n", lock.name, lock.id, id, lock.flag);

	return lock.flag;
}