
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <signal.h>

#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>

 #include <sys/stat.h>
 #include <fcntl.h>

#include <pthread.h>
#include <error.h>

#define LOG_PATH "/var/logtest"

int loop = 1;

void stop_main(int sig)
{
	loop =0;

}

void pipe_sig(int sig)
{
	printf("catch SIGPIPE, %d\n", sig);
}

void *thread_send_msg(void *arg)
{
	printf("arg = %s\n", arg);
	int t = 0;

	t = atoi(arg);
	if(t == 0)
		t = 2;

	sleep(1);
	
	int fd = -1, len =0;
	struct sockaddr_un ser_sockaddr, cli_sockaddr;
	int rtn = 0;
	char buf[1024] = {0};

	while(1)
	{
		memset(buf, 0x0, sizeof(buf));
		fd = socket(AF_UNIX, SOCK_STREAM, 0);

		if(fd < 0)
		{
			printf("socket error\n");
			return ;
		}

		memset(&ser_sockaddr, 0x0, sizeof(ser_sockaddr));
		strncpy(ser_sockaddr.sun_path, LOG_PATH, sizeof(ser_sockaddr.sun_path) - 1);
		ser_sockaddr.sun_family = AF_UNIX;
		
		rtn = connect(fd, (struct sockaddr *)&ser_sockaddr, sizeof(ser_sockaddr));
		if(rtn == -1)
		{
			perror("pthread--:");
			printf("connect error, fd=%d,%d---\n", t, fd);
			close(fd);
			return ;
		}

		sprintf(buf, "From %d , hello", t);
		write(fd, buf, strlen(buf));
		memset(buf, 0x0, sizeof(buf));
		rtn = read(fd, buf, sizeof(buf));
		printf("%d : read %d B, is : %s\n", t, rtn, buf);
		
		close(fd);
		sleep(t);
	}
}

int main(int argc, char *argv[])
{

	int fd = -1;
	struct sockaddr_un sockaddr;
	int len = 0;
	int rtn = -1;

	fd_set rd_fd;
	int cli_fd[10] = {-1};
	struct timeval timeout;

	struct sockaddr_un client;
	int new_fd = -1;
	char msg_buf[1024] = {0};

	int i = 1;
	
	alarm(60);
	signal(SIGALRM, stop_main);

	unlink(LOG_PATH);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(fd < 0)
	{
		printf("socket error \n");
		return 0;
	}

	memset(&sockaddr, 0x0, sizeof(sockaddr));
	strncpy(sockaddr.sun_path, LOG_PATH, sizeof(sockaddr.sun_path) - 1);
	sockaddr.sun_family = AF_UNIX;

	rtn = bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
	perror("bind---");
	printf("**** rtn=%d  ****\n",rtn);

	listen(fd, 5);

	pthread_t td1;
	pthread_t td2;

	rtn = pthread_create(&td1, NULL, thread_send_msg, "2");
	if(rtn != 0)
	{
		printf("create thread 1 failed\n");
	}

	//rtn = pthread_create(&td2, NULL, thread_send_msg, "3");
	if(rtn != 0)
	{
		printf("create thread 2 failed\n");
	}
	
	while(loop)
	{
		memset(msg_buf, 0x0, sizeof(msg_buf));
		memset(&client, 0x0, sizeof(client));
		memset(&cli_fd, 0x0, sizeof(cli_fd));
		FD_ZERO(&rd_fd);
		FD_SET(fd, &rd_fd);
		timeout.tv_sec = 2;
		timeout.tv_usec = 0;


		rtn = select(fd + 1, &rd_fd, NULL, NULL, &timeout);
		perror("select:");
		printf("\n\ntimeout=%d\n\n", timeout.tv_sec);
		if(rtn < 0)
		{
			printf("select little error, continue\n");
			continue;
		}
		else if(rtn == 0)
		{
			printf("select timeout, continue\n");
			continue;
		}

		if(FD_ISSET(fd, &rd_fd))
		{
			/* do real work now */
			len = 1;
			new_fd = accept(fd, (struct sockaddr *)&(client), &len);
			//printf("rtn=%d,len=%d,fd = %d, new_fd=%d, sizeof(client)=%d, sizeof(struct sockaddr)=%d\n", 
			//		rtn, len, fd, new_fd, sizeof(struct sockaddr_un), sizeof(struct sockaddr));
			if(new_fd < 0)
			{
				perror("accept error:");
				continue;
			}
			rtn = read(new_fd, msg_buf, sizeof(msg_buf) - 1);
			printf("MAIN : read %d byte, is : %s \n", rtn , msg_buf);

			write(new_fd, "recive success", sizeof("recive success"));
			
			close(new_fd);
		}
		else
		{
			printf("what happen?\n");
		}
	}//end of while(loop)

	return 0;
}
