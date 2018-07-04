#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]){
	int fd = -1;
	if (argv[1] == NULL){
		fprintf(stderr, "argv[1] is NULL\n");
		exit(0);
	}
	fd = open(argv[1], O_WRONLY);
	if (fd < 0){
		fprintf(stderr, "fail to open file %s\n", argv[1]);
		exit(0);	
	}
	
	char buf[100];
	scanf("%s", buf);
	int i;
	scanf("%d", &i);
	struct flock lock = {F_WRLCK, SEEK_SET, 0, 0, 0}, 
		     rtest, wtest;
	lock.l_pid = getpid();
	rtest = lock;
	wtest = lock;
	rtest.l_type = F_RDLCK;
	fcntl(fd, F_GETLK, &rtest);	
	fcntl(fd, F_GETLK, &wtest);	
	while(rtest.l_type != F_UNLCK || 
		wtest.l_type != F_UNLCK){
		fprintf(stderr, "file %s has been locked\nwaiting for retry...\n", argv[1]);
		sleep(3);
		rtest.l_type = F_RDLCK;
		wtest.l_type = F_WRLCK;
		fcntl(fd, F_GETLK, &wtest);
		fcntl(fd, F_GETLK, &rtest);
	}

	fprintf(stderr, "wait to get lock\n");
	if (fcntl(fd, F_SETLK, &lock) == -1){
		fprintf(stderr, "fail to lock the file %s\n", argv[1]);
		exit(0);
	}
	fprintf(stderr, "get lock\n");
	//int fd1 = -1;
	//fd1 = open(argv[1], O_WRONLY);
	//close(fd1);
	sleep(60);
/*	while(i--){
		if (write(fd, buf, strlen(buf)) < 0){
			fprintf(stderr, "fail to write into file %s\n", argv[1]);
			exit(0);
		}
	}
*/	lock.l_type = F_UNLCK;
	fcntl(fd, F_SETLKW, &lock);
	close(fd);
	return 0;
}
