/*
	Functions For Get system version , build time etc.


	E-mail wangxinyu.yy@gmial.com
	2014.08.22
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "../../svn_version.h"
#include "../../fw_version.h"

/*
	These macros will be define in svn_version.h And fw_version.h.
*/
#ifndef SOFT_WARE_VERSION
#define SOFT_WARE_VERSION "V1.0.0.1"
#endif

#ifndef HW_VERSION
#define HW_VERSION "V1.0"
#endif

#ifndef LANGUAGE_INFO
#define LANGUAGE_INFO "cn"
#endif

#ifndef SVN_VERSION
#define SVN_VERSION "657"
#endif


#define SYSTEM_VERSION_FILE "/var/system_version"

static int get_key_value(const char *key, char *value)
{
	FILE *fp = NULL;
	char buf[256] = {0};
	char *p = NULL;
	int findFlg = 0;

	fp = fopen(SYSTEM_VERSION_FILE, "r");
	if(NULL == fp)
	{
		printf("failed to open %s\n", SYSTEM_VERSION_FILE);
		return -1;
	}

	while(NULL != fgets(buf, sizeof(buf) - 1, fp))
	{
		if(NULL != strstr(buf, key) )
		{	
			p = buf + strlen(key);
			/* skip space */
			p++;
			sprintf(value, "%s", p);
			if(p = strchr(value, '\n'))
				*p = '\0';
			findFlg = 1;
			break;
		}
		memset(buf, 0x0, sizeof(buf));
	}
	
	fclose(fp);

	if(findFlg)
		return strlen(value);

	/* not find */
	return -1;
}

char *get_soft_version(void)
{
	static char version[32] = {0};
	int ret = 0;

	ret = get_key_value("SOFT_WARE_VERSION", version);

	if(ret < 0)
		sprintf(version, "Unkown version");

	return version;
}

char *get_hardware_version(void)
{
	static char version[32] = {0};
	int ret = 0;

	ret = get_key_value("HW_VERSION", version);

	if(ret < 0)
		sprintf(version, "V1.0");

	return version;
}

char *get_svn_version(void)
{
	static char version[32] = {0};
	int ret = 0;

	ret = get_key_value("SVN_VERSION", version);

	if(ret < 0)
		sprintf(version, "657");

	return version;
}

char *get_language_info(void)
{
	static char info[32] = {0};
	int ret = 0;

	ret = get_key_value("LANGUAGE_INFO", info);

	if(ret < 0)
		sprintf(info, "--");

	return info;
}


char *get_build_time(void)
{
	static char buildTime[64] = {0};

	sprintf(buildTime, "%s %s", __DATE__, __TIME__);

	return buildTime;
}


int record_system_version(void)
{
	FILE *fp = NULL;
	char buf[256] = {0};

	fp = fopen(SYSTEM_VERSION_FILE, "w");
	if(NULL == fp)
	{
		printf("failed to open %s\n", SYSTEM_VERSION_FILE);
		return -1;
	}
	
	sprintf(buf, "SOFT_WARE_VERSION %s\n", SOFT_WARE_VERSION);
	fputs(buf, fp);
	
	sprintf(buf, "LANGUAGE_INFO %s\n", LANGUAGE_INFO);
	fputs(buf, fp);

	
	sprintf(buf, "HW_VERSION %s\n", HW_VERSION);
	fputs(buf, fp);

	sprintf(buf, "SVN_VERSION %s\n", SVN_VERSION);
	fputs(buf, fp);

	sprintf(buf, "BUILD_TIME %s\n", get_build_time());
	fputs(buf, fp);
	
	fclose(fp);
	
	return 0;
}


int print_system_version(void)
{
	FILE *fp = NULL;
	char buf[256] = {0};

	fp = fopen(SYSTEM_VERSION_FILE, "r");
	if(NULL == fp)
	{
		printf("failed to open %s\n", SYSTEM_VERSION_FILE);
		return -1;
	}

	while(fgets(buf, sizeof(buf) - 1, fp))
	{
		printf("###  %s", buf);
		fflush(stdout);
		memset(buf, 0x0, sizeof(buf));
	}

	fclose(fp);
	
	return 0;
}

#if 0
static int usage_page(char *base)
{
	printf("Cmd like below:\n");
	
	printf("%s sver\n", base);
	printf("%s hver\n", base);
	printf("%s lang\n", base);
	printf("%s svn\n", base);
	printf("%s buildtime\n", base);
	
	return 0;
}


int main(int argc , char *argv[])
{
	struct stat st;
	char buf[256] = {0};

	if(stat(SYSTEM_VERSION_FILE, &st) < 0)
		record_system_version();	

	if(1 == argc)
	{
		print_system_version();		
		return 0;
	}

	if(2 == argc)
	{
		if(!strcmp(argv[1], "sver"))
		{
			printf("%s : %s\n", argv[1], get_soft_version());
		}
		else if(!strcmp(argv[1], "hver"))
		{
			printf("%s : %s\n", argv[1], get_hardware_version());
		}
		else if(!strcmp(argv[1], "svn"))
		{
			printf("%s : %s\n", argv[1], get_svn_version());
		}
		else if(!strcmp(argv[1], "lang"))
		{
			printf("%s : %s\n", argv[1], get_language_info());
		}
		else if(!strcmp(argv[1], "buildtime"))
		{
			printf("%s : %s\n", argv[1], get_build_time());
		}
		else
		{
			usage_page(argv[0]);
		}

	}

	return 0;
}

#endif

