　  1. A类地址
　　⑴ A类地址第1字节为网络地址，其它3个字节为主机地址。另外第1个字节的最高位固定为0。
　　⑵ A类地址范围：1.0.0.1到126.255.255.254。
　　⑶ A类地址中的私有地址和保留地址：
　　①10.0.0.0到10.255.255.255是私有地址（所谓的私有地址就是在互联网上不使用，而被用在局域网络中的地址）。
　　② 127.0.0.0到127.255.255.255是保留地址，用做循环测试用的。
　　2. B类地址 
　　⑴ B类地址第1字节和第2字节为网络地址，其它2个字节为主机地址。另外第1个字节的前两位固定为10。
　　⑵ B类地址范围：128.0.0.1到191.255.255.254。
　　⑶ B类地址的私有地址和保留地址
　　① 172.16.0.0到172.31.255.255是私有地址
　　②169.254.0.0到169.254.255.255是保留地址。如果你的IP地址是自动获取IP地址，而你在网络上又没有找到可用的DHCP服务器，
这时你将会从169.254.0.0到169.254.255.255中临得获得一个IP地址。
　　3. C类地址
　　⑴ C类地址第1字节、第2字节和第3个字节为网络地址，第4个个字节为主机地址。另外第1个字节的前三位固定为110。
　　⑵ C类地址范围：192.0.0.1到223.255.255.254。
　　⑶ C类地址中的私有地址：192.168.0.0到192.168.255.255是私有地址


私有ip地址:
　　1 10.0.0.0到10.255.255.255
　　2 127.0.0.0到127.255.255.255
　　3 172.16.0.0到172.31.255.255
　　4 169.254.0.0到169.254.255.255 
	5 192.168.0.0到192.168.255.255
	如果你的IP地址是自动获取IP地址，而你在网络上又没有找到可用的DHCP服务器，这时你将会从169.254.0.0到169.254.255.255中临得获得一个IP地址。