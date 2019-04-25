/* For test my common lib */

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char *argv[])
{
	int ret = 0;
	char ip[64] = {0};
	int mtu = -1;
	
	ret = getInterfaceIp("eth1", ip);

	printf("ret = %d, ip=%s\n", ret , ip);

	ret = checkFileExist("/dev/ppp");
	if(ret == 0)
		printf("not exist\n");
	else
		printf("Exist\n");

	printf("ppp1 mtu=%d\n", getIfMTU("eth1", &mtu));

    hostname_to_ip("www.qq.com");

    ip_to_hostname("183.3.226.35");
    printf("[%s][%d]\n", __FUNCTION__, __LINE__);
    ip_to_hostname("127.0.0.1");
	return 0;

}










