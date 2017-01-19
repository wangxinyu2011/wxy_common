/* For test my common lib */

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char *argv[])
{
	int ret = 0;
	char ip[64] = {0};
	int mtu = -1;
	
	ret = getIf_Ip("eth1", ip);

	printf("ret = %d, ip=%s\n", ret , ip);

	ret = checkFileExist("/dev/ppp");
	if(ret == 0)
		printf("not exist\n");
	else
		printf("Exist\n");

	printf("ppp1 mtu=%d\n", getIf_MTU("ppp1", &mtu));

	return 0;

}










