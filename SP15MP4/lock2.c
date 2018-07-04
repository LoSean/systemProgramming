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
	fd = open(argv[1], O_RDONLY);
	if (fd < 0){
		fprintf(stderr, "fail to open file %s\n", argv[1]);
		exit(0);	
	}
	
	char buf[100];
	scanf("%s", buf);
	int i;
	scanf("%d", &i);
	struct flock lock = {F_RDLCK, SEEK_SET, 0, 0, 0},
		     rtest;
	lock.l_pid = getpid();
	rtest = lock;
	fcntl(fd, F_GETLK, &rtest);
	while(rtest.l_type != F_UNLCK){
		fprintf(stderr, "file %s has been locked\nwaiting for retry...\n", argv[1]);
		sleep(3);

		rtest.l_type = F_RDLCK;
		fcntl(fd, F_GETLK, &rtest);
	}
	fprintf(stderr, "wait to get lock\n");
	if (fcntl(fd, F_SETLK, &lock) == -1){
		fprintf(stderr, "fail to lock the file %s\n", argv[1]);
		exit(0);
	}
	fprintf(stderr, "get lock\n");
	sleep(10);
	lock.l_type = F_UNLCK;
	fcntl(fd, F_SETLK, &lock);
	close(fd);
	return 0;
}
