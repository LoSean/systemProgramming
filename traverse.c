#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/inotify.h>
#include <libgen.h>
#include "hash.h"
#define MAXLEN 512
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

static char *fullPath;
static size_t pathLen;

static hash pathHash;

void traverse(char *pathName, int layer, int fd, hash *pHash){
	printf("layer [%d]\n", layer);
	struct stat statbuf;
	int curPathLen = strlen(fullPath);
	printf("curPathLen %d\n", curPathLen);

	if(lstat(pathName, &statbuf) < 0){
		fprintf(stderr, "lstat error\n");
		exit(1);
	}
	if (S_ISDIR(statbuf.st_mode) == 0){
		printf("%s is not a directory.\n", basename(pathName));
		return;
	}

	int wd;
	wd = inotify_add_watch(fd, fullPath, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
	put_into_hash(pHash, (void *)fullPath, wd);
	struct dirent *dirp;
	DIR *dp;
	if((dp = opendir(fullPath)) == NULL){
		fprintf(stderr, "open directory %s failed.\n", basename(fullPath));
		exit(1);
	}
	pathName[curPathLen] = '/';
	pathName[curPathLen+1] = 0;
	while((dirp = readdir(dp)) != NULL){
		if (strcmp(dirp->d_name, ".") == 0 ||
			strcmp(dirp->d_name, "..") == 0)
			continue;
		if(curPathLen + strlen(dirp->d_name) + 1 > pathLen){
			pathLen *= 2;
			fullPath = (char *)realloc(fullPath, pathLen);
		}
		strcpy(&fullPath[curPathLen+1], dirp->d_name);
		traverse(fullPath, layer+1, fd, pHash);
	}
	closedir(dp);
	return;
}

int main(int argc, char *argv[]){
	if(argc != 2){
		fprintf(stderr, "no pathname\n");
		exit(1);
	}
	pathLen = MAXLEN;
	fullPath = (char *)malloc(pathLen);
	strcpy(fullPath, argv[1]);
	
	int fd;
	fd = inotify_init();
 	if (fd < 0) {
    	perror("inotify_init");
	}
	
	init_hash(&pathHash, 97);

	traverse(fullPath, 0, fd, &pathHash);

	char buffer[EVENT_BUF_LEN];
	int length, i = 0;
	int wd;
	memset(buffer, 0, EVENT_BUF_LEN);
	while((length = read(fd, buffer, EVENT_BUF_LEN)) > 0){
		i = 0;
		while(i < length){
			struct inotify_event* event = (struct inotify_event *)&buffer[i];
			printf("event: (%d, %d, %s)\ntype: ", event->wd, strlen(event->name), event->name);
			if (event->mask & IN_CREATE) {
				printf("create ");
			}
			if (event->mask & IN_DELETE) {
				printf("delete ");
			}
			if (event->mask & IN_ATTRIB) {
				printf("attrib ");
			}
			if (event->mask & IN_MODIFY) {
				printf("modify ");
			}
			if (event->mask & IN_ISDIR) {
				char *tmp;
				get_from_hash(&pathHash, (void **)&tmp, event->wd);
				printf("directory path: %s\n", tmp);
				tmp[strlen(tmp)] = '/';
				strcpy(&tmp[strlen(tmp)+1], event->name);
				inotify_add_watch(fd, tmp, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
				printf("dir\n");
			} else {
        			printf("file\n");
			}
			i += EVENT_SIZE + event->len;
		}
		memset(buffer, 0, EVENT_BUF_LEN);
	}
	close(fd);
	return 0;
}
