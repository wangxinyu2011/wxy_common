/*
	Yes , it is Wangxinyu's common lib.

	Make to do something easy,  It really necessary!

	It will be more perfect day by day.

	Date : 2013-4-3
*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <stdarg.h>
#include <ctype.h>

#include<fcntl.h>
#include<unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/reboot.h>
#include <sys/syslog.h>

#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>

#include <dirent.h>

#include <stdarg.h>
#include <errno.h>

#include <limits.h>
#include <signal.h>

#include <sys/wait.h>
#include <sys/ioctl.h>


#define cprintf(fmt, args...) do { \
        FILE *fp = fopen("/dev/console", "w"); \
        if (fp) { \
            fprintf(fp, fmt , ## args); \
            fclose(fp); \
        } \
    } while (0)


int daemon_init(void)
{
    pid_t pid;

    if ((pid = fork()) < 0)
        return(-1);
    else if (pid != 0)
        exit(0); /* parent exit */

    /* child continues */
    setsid(); /* become session leader */
    chdir("/");	/* change working directory */
    umask(0); /* clear file mode creation mask */

    return 0;
}

#define UPTIMEFILE "/proc/uptime"
time_t time_up(time_t *time)
{
    int fd = -1;
    int len = 0;
    char utbuf[64] = {0};
    time_t ret = 0;

    fd = open(UPTIMEFILE, O_RDONLY);
    if ( fd < 0 )
    {
        goto OUT;
    }

    len = read(fd, utbuf, sizeof(utbuf));

    close(fd);

    if (len > 3)
    {
        ret = atoi(utbuf);
    }

OUT:
    if(time)
        *time = ret;
    return ret;
}


void  getCurTime(char *CurDatetime)
{
    struct tm *nowtm = NULL;
    time_t ntime;

    ntime = time(NULL);
    if((nowtm = localtime(&ntime)) != NULL)
    {
        sprintf(CurDatetime, "%04d-%02d-%02d %02d:%02d:%02d",
                nowtm->tm_year + 1900, nowtm->tm_mon + 1, nowtm->tm_mday,
                nowtm->tm_hour, nowtm->tm_min, nowtm->tm_sec);
    }
    else
    {
        sprintf(CurDatetime, "2013-04-06 10:01:06");
    }
}


int getUpTime(void)
{
    int fd = 0, len = 0;
    char utbuf[64] = {0};

    fd = open("/proc/uptime", O_RDONLY);
    if ( fd < 0 )
    {
        return 0;
    }

    len = read(fd, utbuf, sizeof(utbuf));
    close(fd);

    if (len > 3)
    {
        return atoi(utbuf);
    }

    return 0;
}

/*
	Like : 2013-04-07
*/
int setSystemTime(char *date)
{
    int year = 0, mon = 0, day = 0;
    int ret = 0;
    struct tm new_t;
    struct timeval tv;

    if(date == NULL)
        return -1;

    ret = sscanf(date, "%d-%d-%d", &year, &mon, &day);

    printf("%d, %d, %d\n", year, mon, day);
    if(ret != 3)
    {
        printf("wrong format of %s\n", __FUNCTION__);
        return -1;
    }

    new_t.tm_year = year - 1900;
    new_t.tm_mon = mon - 1;
    new_t.tm_mday = day;
    new_t.tm_hour = 0;
    new_t.tm_min = 0;
    new_t.tm_sec = 0;

    tv.tv_sec = mktime(&new_t);
    tv.tv_usec = 0;

    if(settimeofday(&tv, (struct timezone *)NULL) < 0)
    {
        printf("settimeofday error\n");
        return -1;
    }

    return 0;
}

void log_cmd(char *cmdLog)
{
    FILE *fp = NULL;
    time_t ti = 0;

    fp = fopen("/var/cmd.log", "a+");
    if (fp == NULL)
        return;

    ti = time(NULL);
    fprintf(fp, "\n%s     %s\n", ctime(&ti), cmdLog);

    fclose(fp);

    return;
}

int doSystemCmd(char *fmt, ...)
{
    va_list vargs;
    int ret = 0;
    char CmdBuf[512] = {0};
    struct stat st;

    va_start(vargs, fmt);

    ret = vsnprintf(CmdBuf, sizeof(CmdBuf), fmt, vargs);

    va_end(vargs);

    if(stat("/var/cmdout", &st) == 0)
        printf("%s\n", CmdBuf);

    system(CmdBuf);

    return ret;
}


int doShell(char *cmdbuf, char *outbuf, int buflen)
{
    FILE *fp = NULL;
    int ilen = 0, lentmp = 0;
    char tmpbuf[256];

    fp = popen(cmdbuf, "r");
    if (fp == NULL)
    {
        return -1;
    }

    for (;;)
    {
        memset(tmpbuf, 0, sizeof(tmpbuf));
        if (fgets(tmpbuf, sizeof(tmpbuf), fp) == NULL)
            break;
        lentmp = strlen(tmpbuf);

        if ((ilen + lentmp + 1) > buflen)
            break;
        memcpy(outbuf + ilen, tmpbuf, lentmp);
        ilen += lentmp;
    }

    pclose(fp);

    *(outbuf + ilen) = '\0';

    return ilen;
}


typedef struct
{
    int pid;
    char user[32];
} procps_status_t;

int get_proc_pid_self(char *proc_name)
{
    DIR *dir = NULL;
    struct dirent *entry;
    char *name;
    char fpath[128] = {0};

    char buf[1024] = {0};
    FILE *fp = 0;
    procps_status_t curstatus;
    int pid = 0;
    struct stat sb;
    int iRtn = 0;

    dir = opendir("/proc");
    if(!dir)
        return iRtn;

    for(;;)
    {
        if((entry = readdir(dir)) == NULL)
        {
            closedir(dir);
            dir = NULL;
            return iRtn;
        }
        name = entry->d_name;

        if (!(*name >= '0' && *name <= '9'))
            continue;

        memset(&curstatus, 0, sizeof(procps_status_t));
        pid = atoi(name);
        curstatus.pid = pid;

        sprintf(fpath, "/proc/%d", pid);
        if(stat(fpath, &sb) != 0)
            continue;

        sprintf(fpath, "/proc/%d/stat", pid);
        if((fp = fopen(fpath, "r")) == NULL)
            continue;

        name = fgets(buf, sizeof(buf), fp);
        fclose(fp);

        if(name == NULL)
            continue;
        name = strrchr(buf, ')'); /* split into "PID (cmd" and "<rest>" */
        if(name == NULL || name[1] != ' ')
            continue;
        *name = 0;

        memset(&curstatus, 0, sizeof(procps_status_t));
        sscanf(buf, "%d (%31c", &curstatus.pid, curstatus.user);
        if (strcasecmp(curstatus.user, proc_name) == 0)
        {
            iRtn = curstatus.pid;
            break;
        }
    }

    if(dir)
        closedir(dir);
    return iRtn;
}

int get_proc_pid(char *proc_name)
{
    int pid = 0;
    int i = 0;

    for (i = 0; i < 10; i ++)
    {
        pid = get_proc_pid_self(proc_name);
        if (pid > 0)
        {
            return pid;
        }
        else
        {
            usleep(5000);
        }
    }

    return 0;
}

int send_signal(char *app_name, int sig_id)
{
    int pid = 0;

    pid = get_proc_pid(app_name);
    if(pid > 0)
    {
        kill(pid, sig_id);
    }
    else
    {
        return 0;
    }

    return 0;
}

int check_app(char *proc_name)
{
    if (get_proc_pid(proc_name) > 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int killProcByPidFile(const char *pid_file, int sig)
{
    FILE *fp;
    int pid = 0;

    printf("%s ", pid_file);

    fp = fopen(pid_file, "r");

    if(fp)
    {
        fscanf(fp, "%d", &pid);

        printf("%d \n", pid);

        if(pid != 0 && pid != 1)
        {
            kill(pid, sig);
        }

        fclose(fp);

        return 0;
    }
    else
    {
        return -1;
    }

}


int checkFileExist(char *fileName)
{
    struct stat st;

    if(fileName == NULL)
        return 0;
    if(stat(fileName, &st) == 0)
    {
        return 1; //exist
    }
    else
    {
        return 0;
    }
}

int checkModuleExist(char *modName)
{
    char line[128] = {0};
    char buf[64] = {0};
    FILE *fp = NULL;

    fp = fopen("/proc/modules", "r");
    if(fp)
    {
        memset(line, 0x00, sizeof(line));
        memset(buf, 0x00, sizeof(buf));

        while(fgets(line, sizeof(line), fp))
        {
            sscanf(line, "%s *", buf);
            if(strncmp(buf, modName, sizeof(buf)) == 0)
            {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }

    return 0;
}

int getIfMTU(char *IfName, int *mtu)
{
    struct ifreq ifreq;
    int sockfd = 0;
    int ret = -1;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
    {
        strncpy(ifreq.ifr_name, IfName, IFNAMSIZ);

        if ((ret = ioctl(sockfd, SIOCGIFMTU, &ifreq)) >= 0)
        {
            *mtu = ifreq.ifr_mtu;
        }
        else
        {
            perror("getIf_MTU:");
        }

        close(sockfd);
    }

    return *mtu;
}

int getInterfaceIp(char *IfName, char *IP)
{
    struct ifreq ifreq;
    int sockfd = 0;
    int ret = -1;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
    {
        strncpy(ifreq.ifr_name, IfName, IFNAMSIZ);

        if ((ret = ioctl(sockfd, SIOCGIFADDR, &ifreq)) >= 0)
        {
            strcpy(IP, inet_ntoa(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr));
        }
        else
        {
            perror("getIf_Ip:");
        }

        close(sockfd);
    }

    return ret;
}

int getInterfaceMask(char *IfName, char *mask)
{
    struct ifreq ifreq;
    int sockfd = 0;
    int ret = -1;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
    {
        strncpy(ifreq.ifr_name, IfName, IFNAMSIZ);

        if ((ret = ioctl(sockfd, SIOCGIFNETMASK, &ifreq)) >= 0)
        {
            strcpy(mask, inet_ntoa(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr));
        }
        close(sockfd);
    }

    return ret;
}

int getInterfaceMac(char *IfName, char *mac)
{
    struct ifreq ifreq;
    int sockfd;
    int ret = -1;

    unsigned char *pbuf;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
    {
        strncpy(ifreq.ifr_name, IfName, IFNAMSIZ);
        if ((ret = ioctl(sockfd, SIOCGIFHWADDR, &ifreq)) >= 0)
        {
            pbuf = (u_char *)&ifreq.ifr_ifru.ifru_hwaddr.sa_data[0];
            sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                    *pbuf, *(pbuf + 1), *(pbuf + 2), *(pbuf + 3), *(pbuf + 4), *(pbuf + 5));
        }
        close(sockfd);
    }

    return ret;
}

int getInterfaceNetMac(char *ifname, unsigned char *if_mac)
{
    struct ifreq ifr;
    int skfd = 0;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0)
    {
        close(skfd);
        return -1;
    }

    memcpy(if_mac, ifr.ifr_hwaddr.sa_data, 6);
    close(skfd);
    return 0;

}


int getDnsFromFile(char *dns1, char *dns2, char *path)
{
    FILE *fp = NULL;
    char buf[64] = {'\0'};
    char tmp[32] = {'\0'};
    char *resolve = "/etc/resolv.conf";

    int ndns = 0;

    if(path == NULL)
        path = resolve;
    if(dns1 == NULL || dns2 == NULL)
        return 0;
    else
        *dns1 = *dns2 = '\0';

    if((fp = fopen(path, "r")) == NULL)
        return 0;

    while(fgets(buf, sizeof(buf), fp) != NULL)
    {
        if(strncmp(buf, "nameserver", strlen("nameserver")) == 0)
        {
            memset(tmp, 0, 24);
            sscanf(buf, "nameserver %s\n", tmp);

            if(ndns == 0)
                strcpy(dns1, tmp);
            else if(ndns == 1)
                strcpy(dns2, tmp);
            else
                break;

            ndns ++;
        }
    }

    fclose(fp);

    return ndns;
}


int getArpIpMac(char *ipaddr, char *if_hw)
{
    char   buff[256];
    char   tmp1[64];
    char   tmp2[64];
    char   tmp3[64];
    char   tmp4[64];
    char   tmp5[64];
    char   tmp6[64];
    int     findflag = 0;
    int ret = 0;

    FILE *fp = NULL;

    fp = fopen("/proc/net/arp", "r");

    while (fgets(buff, sizeof(buff), fp) != NULL)
    {
        ret = sscanf(buff, "%s%s%s%s%s%s", tmp1, tmp2, tmp3, tmp4, tmp5, tmp6);
        printf("--%s%s%s%s%s%s--,ret=%d\n", tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, ret);
        if (strcmp(tmp1, ipaddr) == 0)
        {
            strcpy(if_hw, tmp4);
            findflag = 1;
            break;
        }
    }

    if (fp)
        fclose(fp);

    if (findflag == 0)
    {
        strcpy(if_hw, "00:00:00:00:00:00");
    }
    return 0;
}


int readValueByName(char *name, char *value, char *file)
{
    FILE *fp = NULL;
    char buf[256] = {0};
    char *p = NULL;

    fp = fopen(file, "r");
    if(fp == NULL)
        return -1;
    //printf("%s:%s\n", __FUNCTION__, name);
    while(fgets(buf, sizeof(buf), fp) != NULL)
    {
        p = strstr(buf, name);
        if(p != NULL)
        {
            p = strchr(buf, '=');
            p++;
            strcpy(value, p);
            if((p = strchr(value, '\n')))
                * p = '\0';
            //printf("name = %s, valude = %s\n", name, value);
            if(fp)
                fclose(fp);
            return 1;
        }

    }

    if(fp)
        fclose(fp);

    return -1;
}

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
/*
 * Convert Ethernet address string representation to binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx notation
 * @param	e	binary data
 * @return	TRUE if conversion was successful and FALSE otherwise
 */
int ether_atoe(const char *a, unsigned char *e)
{
    char *c = (char *) a;
    int i = 0;

    memset(e, 0, ETHER_ADDR_LEN);
    for (;;)
    {
        e[i++] = (unsigned char) strtoul(c, &c, 16);
        if (!*c++ || i == ETHER_ADDR_LEN)
            break;
    }

    return (i == ETHER_ADDR_LEN);
}

/*
 * Convert Ethernet address binary data to string representation
 * @param	e	binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx notation
 * @return	a
 */
char *ether_etoa(const unsigned char *e, char *a)
{
    char *c = a;
    int i;

    for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
        if (i)
            *c++ = ':';
        c += sprintf(c, "%02X", e[i] & 0xff);
    }

    return a;
}

/*
	opt : 1 is appen
		  0 is create new
*/
void write2file(char *filename, int opt, char *fmt, ...)
{
    FILE *fp = NULL;
    va_list vargs;

    if (opt)
    {
        fp = fopen(filename, "a+");
    }
    else
    {
        fp = fopen(filename, "w");
    }

    if (fp == NULL)
    {
        return;
    }

    va_start(vargs, fmt);
    vfprintf(fp, fmt, vargs);
    va_end(vargs);

    fclose(fp);

    return;
}



void strtolower(char *srcstr, char *dststr)
{
    while(*srcstr != '\0')
    {
        *(dststr++) = tolower(*(srcstr++));
    }
    *dststr = '\0';
}

void strtoupper(char *srcstr, char *dststr)
{
    while(*srcstr != '\0')
    {
        *(dststr++) = toupper(*(srcstr++));
    }
    *dststr = '\0';
}

char *fd2str(int fd)
{
    char *buf = NULL;
    size_t count = 0, n;

    do
    {
        buf = realloc(buf, count + 512);
        n = read(fd, buf + count, 512);

        if (n < 0)
        {
            free(buf);
            buf = NULL;
        }

        count += n;
    }
    while (n == 512);

    close(fd);
    if (buf)
        buf[count] = '\0';

    return buf;
}

char *file2str(const char *path)
{
    int fd = 0;

    if ((fd = open(path, O_RDONLY)) == -1)
    {
        perror(path);
        return NULL;
    }

    return fd2str(fd);
}

/* Waits for a file descriptor to change status or unblocked signal
* @param	fd	file descriptor
* @param	timeout	seconds to wait before timing out or 0 for no timeout
* @return	1 if descriptor changed status or 0 if timed out or -1 on error
*/
int waitfor(int fd, int timeout)
{
    fd_set rfds;
    struct timeval tv = { timeout, 0 };

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    return select(fd + 1, &rfds, NULL, NULL, (timeout > 0) ? &tv : NULL);
}

/*
 * Concatenates NULL-terminated list of arguments into a single
 * commmand and executes it
 * @param	argv	argument list
 * @param	path	NULL, ">output", or ">>output"
 * @param	timeout	seconds to wait before timing out or 0 for no timeout
 * @param	ppid	NULL to wait for child termination or pointer to pid
 * @return	return value of executed command or errno
 */
int _eval(char *const argv[], char *path, int timeout, int *ppid)
{
    pid_t pid;
    int status;
    int fd;
    int flags;
    int sig;

    switch (pid = fork())
    {
        case -1:	/* error */
            perror("fork");
            return errno;

        case 0:		/* child */
            /* Reset signal handlers set for parent process */
            for (sig = 0; sig < (_NSIG - 1); sig++)
                signal(sig, SIG_DFL);

            /* Clean up */
            ioctl(0, TIOCNOTTY, 0);
            close(STDIN_FILENO);
            setsid();

            /* Redirect stdout to <path> */
            if (path)
            {
                flags = O_WRONLY | O_CREAT;
                if (!strncmp(path, ">>", 2))
                {
                    /* append to <path> */
                    flags |= O_APPEND;
                    path += 2;
                }
                else if (!strncmp(path, ">", 1))
                {
                    /* overwrite <path> */
                    flags |= O_TRUNC;
                    path += 1;
                }
                if ((fd = open(path, flags, 0644)) < 0)
                    perror(path);
                else
                {
                    dup2(fd, STDOUT_FILENO);
                    close(fd);
                }
            }

            /* execute command */
            printf("%s\n", argv[0]);
            setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin", 1);
            alarm(timeout);
            execvp(argv[0], argv);
            perror(argv[0]);
            exit(errno);

        default:	/* parent */
            if (ppid)
            {
                *ppid = pid;
                return 0;
            }
            else
            {
                if (waitpid(pid, &status, 0) == -1)
                {
                    if (errno == ECHILD)
                        return 0;
                    perror("waitpid");

                    return errno;
                }
                if (WIFEXITED(status))
                    return WEXITSTATUS(status);
                else
                    return status;
            }
    }
}

/*
 * Concatenates NULL-terminated list of arguments into a single
 * commmand and executes it
 * @param	argv	argument list
 * @return	stdout of executed command or NULL if an error occurred
 */
char *_backtick(char *const argv[])
{
    int filedes[2];
    pid_t pid;
    int status;
    char *buf = NULL;

    /* create pipe */
    if (pipe(filedes) == -1)
    {
        perror(argv[0]);
        return NULL;
    }

    switch (pid = fork())
    {
        case -1:	/* error */
            return NULL;

        case 0:		/* child */
            close(filedes[0]);	/* close read end of pipe */
            dup2(filedes[1], 1);	/* redirect stdout to write end of pipe */
            close(filedes[1]);	/* close write end of pipe */
            execvp(argv[0], argv);
            exit(errno);

            break;
        default:	/* parent */
            close(filedes[1]);	/* close write end of pipe */
            buf = fd2str(filedes[0]);
            waitpid(pid, &status, 0);
            break;
    }

    return buf;
}


/*
 * fread() with automatic retry on syscall interrupt
 * @param	ptr	location to store to
 * @param	size	size of each element of data
 * @param	nmemb	number of elements
 * @param	stream	file stream
 * @return	number of items successfully read
 */
int safe_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t ret = 0;

    do
    {
        clearerr(stream);
        ret += fread((char *)ptr + (ret * size), size, nmemb - ret, stream);
    }
    while (ret < nmemb && ferror(stream) && errno == EINTR);

    return ret;
}

/*
 * fwrite() with automatic retry on syscall interrupt
 * @param	ptr	location to read from
 * @param	size	size of each element of data
 * @param	nmemb	number of elements
 * @param	stream	file stream
 * @return	number of items successfully written
 */
int safe_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t ret = 0;

    do
    {
        clearerr(stream);
        ret += fwrite((char *)ptr + (ret * size), size, nmemb - ret, stream);
    }
    while (ret < nmemb && ferror(stream) && errno == EINTR);

    return ret;
}


/* Copy each token in wordlist delimited by space into word */
#define foreach(word, wordlist, next) \
        for (next = &wordlist[strspn(wordlist, " ")], \
                strncpy(word, next, sizeof(word)), \
                word[strcspn(word, " ")] = '\0', \
                word[sizeof(word) - 1] = '\0', \
                next = strchr(next, ' '); \
                strlen(word); \
                next = next ? &next[strspn(next, " ")] : "", \
                strncpy(word, next, sizeof(word)), \
                word[strcspn(word, " ")] = '\0', \
                word[sizeof(word) - 1] = '\0', \
                next = strchr(next, ' '))


/* In the space-separated/null-terminated list(haystack), try to
 * locate the string "needle"
 */
char *find_in_list(const char *haystack, const char *needle)
{
    const char *ptr = haystack;
    int needle_len = 0;
    int haystack_len = 0;
    int len = 0;

    if (!haystack || !needle || !*haystack || !*needle)
        return NULL;

    needle_len = strlen(needle);
    haystack_len = strlen(haystack);

    while (*ptr != 0 && ptr < &haystack[haystack_len])
    {
        /* consume leading spaces */
        ptr += strspn(ptr, " ");

        /* what's the length of the next word */
        len = strcspn(ptr, " ");

        if ((needle_len == len) && (!strncmp(needle, ptr, len)))
            return (char *) ptr;

        ptr += len;
    }
    return NULL;
}


/**
 *	remove_from_list
 *	Remove the specified word from the list.

 *	@param name word to be removed from the list
 *	@param list Space separated list to modify
 *	@param listsize Max size the list can occupy

 *	@return	error code
 */
int remove_from_list(const char *name, char *list, int listsize)
{
    int listlen = 0;
    int namelen = 0;
    char *occurrence = list;

    if (!list || !name || (listsize <= 0))
        return EINVAL;

    listlen = strlen(list);
    namelen = strlen(name);

    occurrence = find_in_list(occurrence, name);

    if (!occurrence)
        return EINVAL;

    /* last item in list? */
    if (occurrence[namelen] == 0)
    {
        /* only item in list? */
        if (occurrence != list)
            occurrence--;
        occurrence[0] = 0;
    }
    else if (occurrence[namelen] == ' ')
    {
        strncpy(occurrence, &occurrence[namelen + 1 /* space */],
                strlen(&occurrence[namelen + 1 /* space */]) + 1 /* terminate */);
    }

    return 0;
}


/**
 *		add_to_list
 *	Add the specified interface(string) to the list as long as
 *	it will fit in the space left in the list.

 *	NOTE: If item is already in list, it won't be added again.

 *	@param name Name of interface to be added to the list
 *	@param list List to modify
 *	@param listsize Max size the list can occupy

 *	@return	error code
 */
int add_to_list(const char *name, char *list, int listsize)
{
    int listlen = 0;
    int namelen = 0;

    if (!list || !name || (listsize <= 0))
        return EINVAL;

    listlen = strlen(list);
    namelen = strlen(name);

    /* is the item already in the list? */
    if (find_in_list(list, name))
        return 0;

    if (listsize <= listlen + namelen + 1 /* space */ + 1 /* NULL */)
        return EMSGSIZE;

    /* add a space if the list isn't empty and it doesn't already have space */
    if (list[0] != 0 && list[listlen - 1] != ' ')
    {
        list[listlen++] = 0x20;
    }

    strncpy(&list[listlen], name, namelen + 1 /* terminate */);

    return 0;
}




/* Utility function to remove duplicate entries in a space separated list
 */

char *remove_dups(char *inlist, int inlist_size)
{
    char name[256], *next = NULL;
    char *outlist;

    if (!inlist_size)
        return NULL;

    if (!inlist)
        return NULL;

    outlist = (char *) malloc(inlist_size);

    if (!outlist)
        return NULL;

    memset(outlist, 0, inlist_size);

    foreach(name, inlist, next)
    {
        if (!find_in_list(outlist, name))
        {
            if (strlen(outlist) == 0)
            {
                snprintf(outlist, inlist_size, "%s", name);
            }
            else
            {
                strncat(outlist, " ", inlist_size - strlen(outlist));
                strncat(outlist, name, inlist_size - strlen(outlist));
            }
        }
    }

    strncpy(inlist, outlist, inlist_size);

    free(outlist);
    return inlist;

}

char  *pri_itoa(int num, char *s)
{
    char sign = 0, tmp[32] = {0};
    int i = 0, j = 0;

    if(num == 0)
    {
        s[0] = '0';
        return s;
    }
    else if(num < 0)
    {
        sign = 1;
        num = -num;
    }


    for(i = 0; num > 0; i++)
    {
        tmp[i] = num % 10 + '0';
        num /= 10;
        j++;
    }

    if(sign)
    {
        s[0] = '-';
        i = 1;
    }
    else
        i = 0;
    for(; j > 0; i++, j--)
    {

        s[i] = tmp[j - 1];
    }

    return s;
}

int pri_atoi(char *s)
{
    int num = 0;

    if(!s || *s == '\0')
        return -1;

    while(*s >= '0' && *s <= '9')
    {
        num  = num * 10 + *s - '0';
        s++;
    }

    return num;
}


int check_mask(char *mask)
{
    struct in_addr inp;
    unsigned long num = 0;
    int i = 0, flag = 1, net_bit = 0;

    if(!mask)
    {
        printf("mask is NULL, %s\n", __FUNCTION__);
        return 0;
    }

    if(inet_aton(mask, &inp) == 0)
    {
        printf("mask is invalid, %s\n", __FUNCTION__);
        return 0;
    }
    num = ntohl(inp.s_addr);

    for(i = 0; i < 32; i++)
    {
        if(num & (1 << i) == 0)
        {
            if(net_bit == 1)
            {
                flag = 0;
                break;
            }
        }
        else
        {
            net_bit = 1;
        }

    }

    if(!flag)
        return 0;
    return 1;
}


int check_cpu_endian(void)
{
    unsigned int a = 0x12345678;
    char *p = NULL;

    p = (char *)&a;

    if(*p == 0x78)
    {
        printf("Little endian CPU\n");
        return 0;
    }
    else if(*p == 0x12)
    {
        printf("Big endian CPU\n");
        return 1;
    }
    else
    {
        printf("Unknow  endian CPU\n");
    }

    return -1;
}

static int hex2num(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}


static int hex2byte(const char *hex)
{
    int a, b;
    a = hex2num(*hex++);
    if (a < 0)
        return -1;
    b = hex2num(*hex++);
    if (b < 0)
        return -1;
    return (a << 4) | b;
}


/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, unsigned  *addr)
{
    int i;

    for (i = 0; i < 6; i++)
    {
        int a, b;

        a = hex2num(*txt++);
        if (a < 0)
            return -1;
        b = hex2num(*txt++);
        if (b < 0)
            return -1;
        *addr++ = (a << 4) | b;
        if (i < 5 && *txt++ != ':')
            return -1;
    }

    return 0;
}


/**
 * hwaddr_aton2 - Convert ASCII string to MAC address (in any known format)
 * @txt: MAC address as a string (e.g., 00:11:22:33:44:55 or 0011.2233.4455)
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: Characters used (> 0) on success, -1 on failure
 */
int hwaddr_aton2(const char *txt, unsigned char *addr)
{
    int i;
    const char *pos = txt;

    for (i = 0; i < 6; i++)
    {
        int a, b;

        while (*pos == ':' || *pos == '.' || *pos == '-')
            pos++;

        a = hex2num(*pos++);
        if (a < 0)
            return -1;
        b = hex2num(*pos++);
        if (b < 0)
            return -1;
        *addr++ = (a << 4) | b;
    }

    return pos - txt;
}


/**
 * hexstr2bin - Convert ASCII hex string into binary data
 * @hex: ASCII hex string (e.g., "01ab")
 * @buf: Buffer for the binary data
 * @len: Length of the text to convert in bytes (of buf); hex will be double
 * this size
 * Returns: 0 on success, -1 on failure (invalid hex string)
 */
int hexstr2bin(const char *hex, unsigned char *buf, size_t len)
{
    size_t i;
    int a;
    const char *ipos = hex;
    unsigned char *opos = buf;

    for (i = 0; i < len; i++)
    {
        a = hex2byte(ipos);
        if (a < 0)
            return -1;
        *opos++ = a;
        ipos += 2;
    }
    return 0;
}


/**
 * inc_byte_array - Increment arbitrary length byte array by one
 * @counter: Pointer to byte array
 * @len: Length of the counter in bytes
 *
 * This function increments the last byte of the counter by one and continues
 * rolling over to more significant bytes if the byte was incremented from
 * 0xff to 0x00.
 */
void inc_byte_array(unsigned char *counter, size_t len)
{
    int pos = len - 1;
    while (pos >= 0)
    {
        counter[pos]++;
        if (counter[pos] != 0)
            break;
        pos--;
    }
}


#if 0

/*wxy*/

//a little function
int wxy_atoi(const char *dest)
{
    int x = 0;
    int digit;

    if ((*dest == '0') && (*(dest + 1) == 'x'))
    {
        return 0;
    }

    while (*dest)
    {
        if ((*dest >= '0') && (*dest <= '9'))
        {
            digit = *dest - '0';
        }
        else
        {
            break;
        }

        x *= 10;
        x += digit;
        dest++;
    }
    return x;
}


static int getPidFromFile(char *path)
{
    struct file *fp = NULL;
    char tmpbuf[32] = {0};
    pid_t pid = 0;

    if(!path)
        return -1;

    fp = filp_open(path, O_RDONLY, S_IRUSR | S_IWUSR);

    if(IS_ERR(fp))
    {
        return -1;
    }

    fp->f_op->read(fp, tmpbuf, 32, &fp->f_pos);

    filp_close(fp, NULL);

    pid = wxy_atoi(tmpbuf);

    return pid;
}

static int sendProcessSignal(int pid, int sig)
{
    struct task_struct *p_tsk = NULL;

    for_each_process(p_tsk)
    {
        //get httpd task info
        if(p_tsk->pid == pid)
        {
            goto match_process;
        }
    }
    return -1;

match_process:
    send_sig_info(sig, NULL, p_tsk);

    return 0;
}


#endif

/*
	url : "http://www.xx.com.cn:8000/asdf/bin.bin";
*/
int get_path_url(char *upgradePath, char *host, int *port, char *url)
{
    int ret = 0;
    char buff[128] = {0};
    char *p;

    if(upgradePath == NULL || host == NULL || port == NULL ||  url == NULL)
        return -1;
    /*http://120.24.90.5:5018/download/Device/banner3.png */

    p = upgradePath;
    *port = 80;

    if(strstr(p, "http://"))
        p += strlen("http://");

    if(strstr(p, ":"))
        ret = sscanf(p, "%[^:]:%d%s", host, port, url);
    else
        ret = sscanf(p, "%[^/]%s", host, url);

    return 0;
}
typedef struct
{
    char name[20];
    unsigned int user;
    unsigned int nice;
    unsigned int system;
    unsigned int idle;
} CPU_OCCUPY;


int cal_cpuoccupy (CPU_OCCUPY *o, CPU_OCCUPY *n)
{
    unsigned long od, nd;
    unsigned long id, sd;
    int cpu_use = 0;

    od = (unsigned long) (o->user + o->nice + o->system + o->idle);
    nd = (unsigned long) (n->user + n->nice + n->system + n->idle);

    id = (unsigned long) (n->user - o->user);
    sd = (unsigned long) (n->system - o->system);
    if((nd - od) != 0)
        cpu_use = (int)((sd + id) * 100) / (nd - od);
    else
        cpu_use = 0;
    //printf("cpu: %u/n",cpu_use);
    return cpu_use;
}

void get_cpuoccupy (CPU_OCCUPY *cpust)
{
    FILE *fd;
    char buff[256];
    CPU_OCCUPY *cpu_occupy;
    cpu_occupy = cpust;

    fd = fopen ("/proc/stat", "r");
    fgets (buff, sizeof(buff), fd);

    sscanf (buff, "%s %u %u %u %u", cpu_occupy->name, &cpu_occupy->user, &cpu_occupy->nice, &cpu_occupy->system, &cpu_occupy->idle);

    fclose(fd);
}

/*
    Return : CPU use percent
*/
int get_cpu_use()
{
    unsigned int cpu = 0;
    CPU_OCCUPY cpu_stat1;
    CPU_OCCUPY cpu_stat2;


    get_cpuoccupy((CPU_OCCUPY *)&cpu_stat1);
    usleep(10 * 1000);


    get_cpuoccupy((CPU_OCCUPY *)&cpu_stat2);


    cpu = cal_cpuoccupy ((CPU_OCCUPY *)&cpu_stat1, (CPU_OCCUPY *)&cpu_stat2);

    return cpu > 99 ? 90 : cpu;
}
/*
    Get memory total and Free.

    Output :  (KB)
*/
void get_memoccupy (unsigned int *mem_total, unsigned int *mem_free)
{
    FILE *fd;
    char buff[256];


    fd = fopen ("/proc/meminfo", "r");

    fgets (buff, sizeof(buff), fd);
    sscanf (buff, "%*s %u %*s", mem_total);

    fgets (buff, sizeof(buff), fd);
    sscanf (buff, "%*s %u %*s", mem_free);

    fclose(fd);
}

unsigned long resolve_dns_ipv4(char *host_name)
{
    struct hostent *host = NULL;
    struct in_addr addr;
    char **pp;

    host = gethostbyname(host_name);
    if (host == NULL)
    {
        printf("gethostbyname %s failed\n", host_name);
        return 0;
    }

    pp = host->h_addr_list;

    if (*pp != NULL)
    {
        addr.s_addr = *((unsigned int *)*pp);
        printf("address is %s\n", inet_ntoa(addr));
        pp++;
        return addr.s_addr;
    }

    return 1;
}

int ip_to_hostname(const char *ip)
{
    int ret = 0;

    if(!ip)
    {
        printf("invalid params\n");
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *res, *res_p;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME | AI_NUMERICHOST;
    hints.ai_protocol = 0;

    ret = getaddrinfo(ip, NULL, &hints, &res);
    if(ret != 0)
    {
        printf("getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    for(res_p = res; res_p != NULL; res_p = res_p->ai_next)
    {
        char host[1024] = {0};
        ret = getnameinfo(res_p->ai_addr, res_p->ai_addrlen, host, sizeof(host), NULL, 0, NI_NAMEREQD);
        if(ret != 0)
        {
            printf("getnameinfo: %s\n", gai_strerror(ret));
        }
        else
        {
            printf("hostname: %s\n", host);
        }
    }

    freeaddrinfo(res);
    return ret;
}
int hostname_to_ip(const char *hostname)
{
    int ret = 0;

    if(!hostname)
    {
        printf("invalid params\n");
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *res, *res_p;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;

    ret = getaddrinfo(hostname, NULL, &hints, &res);
    if(ret != 0)
    {
        printf("getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    for(res_p = res; res_p != NULL; res_p = res_p->ai_next)
    {
        char host[1024] = {0};
        ret = getnameinfo(res_p->ai_addr, res_p->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        if(ret != 0)
        {
            printf("getnameinfo: %s\n", gai_strerror(ret));
        }
        else
        {
            printf("ip: %s\n", host);
        }
    }

    freeaddrinfo(res);
    return ret;
}
