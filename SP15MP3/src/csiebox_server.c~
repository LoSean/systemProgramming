#include "csiebox_server.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <utime.h>
#include <fcntl.h>
#include <libgen.h>
#include <dirent.h>
static int parse_arg(csiebox_server* server, int argc, char** argv);
static void handle_request(csiebox_server* server, int conn_fd, fd_set *master, int fdmax);
static int get_account_info(
		csiebox_server* server,  const char* user, csiebox_account_info* info);
static int reSyncMeta(char *pathTmp, struct stat statBuf, csiebox_server *server, int conn_fd);
static int reSyncFile(char *pathTmp, struct stat statBuf, csiebox_server *server, int conn_fd);
static int reSyncRm(char *pathTmp, csiebox_server *server, int conn_fd);
static void reSyncEnd(csiebox_server *server, int conn_fd);
static void login(csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void syncMeta(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta,
		fd_set *master,  int fdmax);
static void syncHardLink(csiebox_server* server, int conn_fd, csiebox_protocol_hardlink* hardlink);
static void syncRm(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm, fd_set *master, int fdmax);
static void syncFile(char *pathTmp, csiebox_server* server, int conn_fd, struct stat metaBuf);
static void logout(csiebox_server* server, int conn_fd);
static char* get_user_homedir(
		csiebox_server* server, csiebox_client_info* info);
static void reClientMeta(char *pathTmp, struct stat statBuf, 
		csiebox_server *server, int conn_fd, fd_set *master, int fdmax);
static void reClientRm(char *pathTmp, csiebox_server *server, int conn_fd, fd_set *master, int fdmax);
void traverse(csiebox_server *server, int conn_fd);

#define DIR_S_FLAG (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)//permission you can use to create new file
#define REG_S_FLAG (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)//permission you can use to create new directory

#define MAXLEN 512
#define MAXCONTENT 4096
//read config file, and start to listen
void csiebox_server_init(
		csiebox_server** server, int argc, char** argv) {
	csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
	if (!tmp) {
		fprintf(stderr, "server malloc fail\n");
		return;
	}
	memset(tmp, 0, sizeof(csiebox_server));
	if (!parse_arg(tmp, argc, argv)) {
		fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
		free(tmp);
		return;
	}
	int fd = server_start();
	if (fd < 0) {
		fprintf(stderr, "server fail\n");
		free(tmp);
		return;
	}
	tmp->client = (csiebox_client_info**)
		malloc(sizeof(csiebox_client_info*) * getdtablesize());
	if (!tmp->client) {
		fprintf(stderr, "client list malloc fail\n");
		close(fd);
		free(tmp);
		return;
	}
	memset(tmp->client, 0, sizeof(csiebox_client_info*) * getdtablesize());
	tmp->listen_fd = fd;
	*server = tmp;

}

//wait client to connect and handle requests from connected socket fd
int csiebox_server_run(csiebox_server* server) {
	fd_set master;
	fd_set read_fds;
	int conn_fd, conn_len;
	int fdmax = server->listen_fd;
	struct sockaddr_in addr;

	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	FD_SET(server->listen_fd, &master);

	while (1) {
		read_fds = master;
		if(select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1){
			perror("select.");
			exit(4);
		}
		memset(&addr, 0, sizeof(addr));
		for(int i = 0; i <= fdmax; i++){
			if(FD_ISSET(i, &read_fds)){
				if(i == server->listen_fd){
					conn_len = sizeof(addr);
					// waiting client connect
					conn_fd = accept(
							server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
					if (conn_fd < 0) {
						if (errno == ENFILE) {
							fprintf(stderr, "out of file descriptor table\n");
							continue;
						} else if (errno == EAGAIN || errno == EINTR) {
							continue;
						} else {
							fprintf(stderr, "accept err\n");
							fprintf(stderr, "code: %s\n", strerror(errno));
							break;
						}
					}else{
						fprintf(stderr, "======new conn_fd : %d====\n", conn_fd);
						FD_SET(conn_fd, &master);
						if(conn_fd > fdmax)
							fdmax = conn_fd;
					}
				}else{
				// handle request from connected socket fd
					handle_request(server, i, &master, fdmax);
				}
			}
		}
	}
	return 1;
}

void csiebox_server_destroy(csiebox_server** server) {
	csiebox_server* tmp = *server;
	*server = 0;
	if (!tmp) {
		return;
	}
	close(tmp->listen_fd);
	int i = getdtablesize() - 1;
	for (; i >= 0; --i) {
		if (tmp->client[i]) {
			free(tmp->client[i]);
		}
	}
	free(tmp->client);
	free(tmp);
}

//read config file
static int parse_arg(csiebox_server* server, int argc, char** argv) {
	if (argc != 2) {
		return 0;
	}
	FILE* file = fopen(argv[1], "r");
	if (!file) {
		return 0;
	}
	fprintf(stderr, "reading config...\n");
	size_t keysize = 20, valsize = 20;
	char* key = (char*)malloc(sizeof(char) * keysize);
	char* val = (char*)malloc(sizeof(char) * valsize);
	ssize_t keylen, vallen;
	int accept_config_total = 2;
	int accept_config[2] = {0, 0};
	while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
		key[keylen] = '\0';
		vallen = getline(&val, &valsize, file) - 1;
		val[vallen] = '\0';
		fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
		if (strcmp("path", key) == 0) {
			if (vallen <= sizeof(server->arg.path)) {
				strncpy(server->arg.path, val, vallen);
				accept_config[0] = 1;
			}
		} else if (strcmp("account_path", key) == 0) {
			if (vallen <= sizeof(server->arg.account_path)) {
				strncpy(server->arg.account_path, val, vallen);
				accept_config[1] = 1;
			}
		}
	}
	free(key);
	free(val);
	fclose(file);
	int i, test = 1;
	for (i = 0; i < accept_config_total; ++i) {
		test = test & accept_config[i];
	}
	if (!test) {
		fprintf(stderr, "config error\n");
		return 0;
	}
	return 1;
}

//this is where the server handle requests, you should write your code here
static void handle_request(csiebox_server* server, int conn_fd, fd_set *master, int fdmax) {
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	while(recv_message(conn_fd, &header, sizeof(header))){
		if (header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ) {
			return;
		}
		switch (header.req.op) {
			case CSIEBOX_PROTOCOL_OP_LOGIN:
				fprintf(stderr, "login\n");
				csiebox_protocol_login req;
				if (complete_message_with_header(conn_fd, &header, &req)) {
					login(server, conn_fd, &req);
					traverse(server, conn_fd);
				}
				break;
			case CSIEBOX_PROTOCOL_OP_SYNC_META:
				fprintf(stderr, "sync meta\n");
				csiebox_protocol_meta meta;
				if (complete_message_with_header(conn_fd, &header, &meta)) {
					syncMeta(server, conn_fd, &meta, master, fdmax);
					//====================
					//        TODO
					//====================
					fprintf(stderr, "meta completed.\n");
				}
				break;
			case CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK:
				fprintf(stderr, "sync hardlink\n");
				csiebox_protocol_hardlink hardlink;
				if (complete_message_with_header(conn_fd, &header, &hardlink)) {
					syncHardLink(server, conn_fd, &hardlink);
					//====================
					//        TODO
					//====================
				}
				break;
			case CSIEBOX_PROTOCOL_OP_SYNC_END:
				fprintf(stderr, "sync end\n");
				csiebox_protocol_header end;
				return;
				//====================
				//        TODO
				//====================
				break;
			case CSIEBOX_PROTOCOL_OP_RM:
				fprintf(stderr, "rm\n");
				csiebox_protocol_rm rm;
				if (complete_message_with_header(conn_fd, &header, &rm)) {
					syncRm(server, conn_fd, &rm, master, fdmax);
					//====================
					//        TODO
					//====================
				}
				break;
			default:
				fprintf(stderr, "unknown op %x\n", header.req.op);
				break;
		}
	}
	logout(server, conn_fd);
	FD_CLR(conn_fd, master);	
	fprintf(stderr, "end of connection\n");
}

//open account file to get account information
static int get_account_info(
		csiebox_server* server,  const char* user, csiebox_account_info* info) {
	FILE* file = fopen(server->arg.account_path, "r");
	if (!file) {
		return 0;
	}
	size_t buflen = 100;
	char* buf = (char*)malloc(sizeof(char) * buflen);
	memset(buf, 0, buflen);
	ssize_t len;
	int ret = 0;
	int line = 0;
	while ((len = getline(&buf, &buflen, file) - 1) > 0) {
		++line;
		buf[len] = '\0';
		char* u = strtok(buf, ",");
		if (!u) {
			fprintf(stderr, "illegal form in account file, line %d\n", line);
			continue;
		}
		if (strcmp(user, u) == 0) {
			memcpy(info->user, user, strlen(user));
			char* passwd = strtok(NULL, ",");
			if (!passwd) {
				fprintf(stderr, "illegal form in account file, line %d\n", line);
				continue;
			}
			md5(passwd, strlen(passwd), info->passwd_hash);
			ret = 1;
			break;
		}
	}
	free(buf);
	fclose(file);
	return ret;
}

//handle the login request from client
static void login(
		csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
	int succ = 1;
	csiebox_client_info* info =
		(csiebox_client_info*)malloc(sizeof(csiebox_client_info));
	memset(info, 0, sizeof(csiebox_client_info));
	if (!get_account_info(server, login->message.body.user, &(info->account))) {
		fprintf(stderr, "cannot find account\n");
		succ = 0;
	}
	if (succ && memcmp(login->message.body.passwd_hash,info->account.passwd_hash,
				MD5_DIGEST_LENGTH) != 0) {
		fprintf(stderr, "passwd miss match\n");
		succ = 0;
	}

	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_LOGIN;
	header.res.datalen = 0;
	if (succ) {
		if (server->client[conn_fd]) {
			free(server->client[conn_fd]);
		}
		info->conn_fd = conn_fd;
		server->client[conn_fd] = info;
		header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
		header.res.client_id = info->conn_fd;
		char* homedir = get_user_homedir(server, info);
		mkdir(homedir, DIR_S_FLAG);
		free(homedir);
	} else {
		header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
		free(info);
	}
	send_message(conn_fd, &header, sizeof(header));
}

static char *fullPath;
static size_t pathLen;
static int reLen;

static int reSyncFile(char *pathTmp, struct stat statBuf, csiebox_server *server, int conn_fd){
	csiebox_protocol_file file;
	memset(&file, 0, sizeof(file));
	file.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	file.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
	file.message.header.req.datalen = sizeof(file) - sizeof(file.message.header);
	
	char contentBuf[MAXCONTENT];
	memset(contentBuf, 0, MAXCONTENT);
	if(S_ISLNK(statBuf.st_mode)){
		fprintf(stderr, "[reSyncFile] soft link .\n");
		readlink(pathTmp, contentBuf, MAXCONTENT);
		file.message.body.datalen = strlen(contentBuf);
		fprintf(stderr, "[reSyncFile] %s %d\n", contentBuf, strlen(contentBuf));
	}
	else{
		int fd = open(pathTmp, O_RDONLY);
		if (fd < 0)
			return 0;
		file.message.body.datalen = read(fd, contentBuf, MAXCONTENT);
		close(fd);
	}
	fprintf(stderr, "[reSyncFile]file %s length : %d\n", pathTmp, file.message.body.datalen);
	if(!send_message(conn_fd, &file, sizeof(file))){
		fprintf(stderr, "[reSyncFile]send failed.\n");	
		return 0;
	}
	if(file.message.body.datalen == 0){
		fprintf(stderr, "[reSyncFile] file no content.\n");
		return 1;
	}
	if (!send_message(conn_fd, contentBuf, file.message.body.datalen)){
		fprintf(stderr, "[reSyncFile]file content send failed\n");
		return 0;
	}
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if (recv_message(conn_fd, &header, sizeof(header))){
		if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
		        header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_FILE &&
			header.res.status == CSIEBOX_PROTOCOL_STATUS_OK){
			return 1;
		}
		else{
			return 0;
		}
	}
	return 0;
}

static int reSyncMeta(char *pathTmp, struct stat statBuf, csiebox_server *server, int conn_fd){
	csiebox_protocol_meta meta;
	memset(&meta, 0, sizeof(meta));
	meta.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	meta.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	meta.message.header.req.datalen = sizeof(meta) - sizeof(meta.message.header);
	meta.message.body.pathlen = strlen(pathTmp) - reLen;
	printf("[reSyncMeta]meta.message.body.pathlen = %d\n", meta.message.body.pathlen);
	printf("[reSyncMeta]path in meta : %s\n", &pathTmp[reLen]);
	memcpy(&meta.message.body.stat, &statBuf, sizeof(statBuf));
	if(S_ISREG(statBuf.st_mode)){
		if(!md5_file(pathTmp, meta.message.body.hash)){
			fprintf(stderr, "[reSyncMeta]file md5 failed\n");
			exit(1);
		}
	}
	if (!send_message(conn_fd, &meta, sizeof(meta))) {
		fprintf(stderr, "[reSyncMeta]send fail\n");
		return 0;
	}
	
	if (!send_message(conn_fd, &pathTmp[reLen], strlen(&pathTmp[reLen]))){
		fprintf(stderr, "[reSyncMeta]path name send failed\n");
		return 0;
	}
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if (recv_message(conn_fd, &header, sizeof(header))){
		if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
		        header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_META &&
		        header.res.status != CSIEBOX_PROTOCOL_STATUS_FAIL){
			if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK)
				return 1;
			else if(header.res.status == CSIEBOX_PROTOCOL_STATUS_MORE){
				if(reSyncFile(pathTmp, statBuf, server, conn_fd)){			
					return 1;
				}
				else{
					return 0;
				}
			}
			else{
				return 0;
			}
		}
		else{
			return 0;
		}
	}
	return 0;
}

void dotrav(csiebox_server *server, int conn_fd){
	struct stat statBuf;
	if(lstat(fullPath, &statBuf) < 0){
		fprintf(stderr, "lstat error\n");
		exit(1);
	}
	if(S_ISDIR(statBuf.st_mode) == 0){
		fprintf(stderr, "%s is not a directory\n", basename(fullPath));
/*		char getpath[MAXPATH];
		memset(getpath, 0, MAXPATH);
		if(inoTest(fullPath, statBuf, getpath)){
			fprintf(stderr, "[dotrav] hard link found : %s\n", getpath);
			if(!syncHardLink(fullPath, getpath, client)){
				fprintf(stderr, "syncHardLink in traverse failed\n");
				exit(1);
			}
			fprintf(stderr, "[dotrav] hard link success.\n");
		}
		else{
			fprintf(stderr, "[dotrav] hard link not found.\n");
*/			if(!reSyncMeta(fullPath, statBuf, server, conn_fd)){
				fprintf(stderr, "syncMeta in traverse failed\n");
				exit(1);
			}
///		}
		return;
	}

	struct dirent *dirp;
	DIR *dp;
	if((dp = opendir(fullPath)) == NULL){
		fprintf(stderr, "Cannot open the directory %s\n", basename(fullPath));
		return;
	}

	if(strlen(fullPath) > reLen){
		if(!reSyncMeta(fullPath, statBuf, server, conn_fd)){
			fprintf(stderr, "sync directory in traverse failed\n");
			exit(1);
		}
	}


	fprintf(stderr, "current directory: %s\n", fullPath);
	int curPathLen = strlen(fullPath);
	fullPath[curPathLen] = '/';
	fullPath[curPathLen+1] = '0';
	while((dirp = readdir(dp)) != NULL){
		if(strcmp(dirp->d_name, ".") == 0 ||
				strcmp(dirp->d_name, "..") == 0)
			continue;
/*		if(curPathLen + strlen(dirp->d_name) > pathLen){
			pathLen *= 2;
			fullPath = (char *)realloc(fullPath, pathLen);
		}
*/		strcpy(&fullPath[curPathLen+1], dirp->d_name);
		fprintf(stderr, "traverse target: %s\n", fullPath);
		dotrav(server, conn_fd);
	}
	closedir(dp);
	return;
}

void traverse(csiebox_server *server, int conn_fd){
	fullPath = (char *)malloc(MAXLEN);
	sprintf(fullPath, "%s/%s", server->arg.path, server->client[conn_fd]->account.user);
	fprintf(stderr, "before traverse fullPath : %s\n", fullPath);
	reLen = strlen(fullPath);
	dotrav(server, conn_fd);
	reSyncEnd(server, conn_fd);
	free(fullPath);
	return;
}

static void reSyncEnd(csiebox_server *server, int conn_fd){
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
	send_message(conn_fd, &header, sizeof(header));
}

static int reSyncRm(char *pathTmp, csiebox_server *server, int conn_fd){
	csiebox_protocol_rm rm;
	memset(&rm, 0, sizeof(rm));
	rm.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	rm.message.header.req.op = CSIEBOX_PROTOCOL_OP_RM;
	rm.message.header.req.datalen = sizeof(rm) - sizeof(rm.message.header);
	rm.message.body.pathlen = strlen(pathTmp) - reLen;
	if (!send_message(conn_fd, &rm, sizeof(rm))){
		fprintf(stderr, "[reSyncRm] fail to send rm\n");
		return 0;
	}
	fprintf(stderr, "[reSyncRm] &pathTmp[reLen] %s\n", &pathTmp[reLen]);
	if (!send_message(conn_fd, &pathTmp[reLen], rm.message.body.pathlen)){
		fprintf(stderr, "[reSyncRm] fail to send pathTmp\n");
		return 0;
	}
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if (!recv_message(conn_fd, &header, sizeof(header))){
		
		if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
			header.res.op == CSIEBOX_PROTOCOL_OP_RM &&
			header.res.status == CSIEBOX_PROTOCOL_STATUS_OK){
			return 1;
		}
		else{
			return 0;
		}
	}
	return 0;
}

static void reClientRm(char *pathTmp, csiebox_server *server, int conn_fd, fd_set *master, int fdmax){
	csiebox_protocol_header header;
	csiebox_protocol_rm rm;
	for(int i = 0; i <= fdmax; i++){
		if (server->client[i] != NULL){
			if (!strcmp(server->client[i]->account.user,
				    server->client[conn_fd]->account.user) && conn_fd != i){
				reSyncRm(pathTmp, server, i);
				reSyncEnd(server, i);
				handle_request(server, i, master, fdmax);
/*				memset(&rm, 0, sizeof(rm));
				if (!recv_message(i, &rm, sizeof(rm))){
					fprintf(stderr, "[reClientRm] fail to recv rm\n");
				}
				char path[MAXLEN];
				if (!recv_message(i, path, rm.message.body.pathlen)){
					fprintf(stderr, "[reClientRm] fail to recv path\n");
				}
				fprintf(stderr, "[reClientRm] recv path success\n");
				memset(&header, 0, sizeof(header));
				header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
				header.res.op = CSIEBOX_PROTOCOL_OP_RM;
				header.res.datalen = 0;
				header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
				if (!send_message(i, &header, sizeof(header))){
					fprintf(stderr, "[reClientRm] fail to send\n");
					exit(1);
				}
				memset(&header, 0 ,sizeof(header));
				if (!recv_message(i, &header, sizeof(header))){
					fprintf(stderr, "[reClientRm] fail to recv syncEnd\n");
				}
				fprintf(stderr, "[reClientRm] recv syncEnd success\n");
*/			}
		}
	}
}

static void syncRm(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm, fd_set *master, int fdmax){
	char pathTmp[MAXLEN];
	sprintf(pathTmp, "%s/%s", server->arg.path, server->client[conn_fd]->account.user);
	char getPath[MAXLEN];
	int originalLen = strlen(pathTmp);
	fprintf(stderr, "[syncRm] pathlen : %d\n", rm->message.body.pathlen);
	if(recv_message(conn_fd, &pathTmp[originalLen], rm->message.body.pathlen) == 0){
		fprintf(stderr, "[syncRm] rm recv file error\n");
		exit(1);
	}	
	pathTmp[originalLen+rm->message.body.pathlen] = '\0';
	printf("[syncRm] path got from client : %s\n", pathTmp);
	struct stat statbuf;
	int flag = 1;
	if (lstat(pathTmp, &statbuf) < 0){
		flag = 0;
	}
	else{
		if (remove(pathTmp) != 0){
			perror("[syncRm] remove failed : ");
		}
	}

	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_RM;
	header.res.datalen = 0;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	send_message(conn_fd, &header, sizeof(header));
//static int reSyncRm(char *pathTmp, csiebox_server *server, int conn_fd){
	if (flag){
		reClientRm(pathTmp, server, conn_fd, master, fdmax);
	}
	return;
}

static void syncHardLink(csiebox_server* server, int conn_fd, csiebox_protocol_hardlink* hardlink){
	char srcPath[MAXLEN], targetPath[MAXLEN];
	sprintf(srcPath, "%s/%s", server->arg.path, server->client[conn_fd]->account.user);
	sprintf(targetPath, "%s/%s", server->arg.path, server->client[conn_fd]->account.user);
	int originalLen = strlen(srcPath);
	char getPath[MAXLEN];
	if(recv_message(conn_fd, &srcPath[originalLen], hardlink->message.body.srclen) == 0){
		fprintf(stderr, "[syncHardLink] recv src file error\n");
		exit(1);
	}	
	srcPath[originalLen+hardlink->message.body.srclen] = '\0';
	if(recv_message(conn_fd, &targetPath[originalLen], hardlink->message.body.targetlen) == 0){
		fprintf(stderr, "[syncHardLinki] recv target file error\n");
		exit(1);
	}
	targetPath[originalLen+hardlink->message.body.targetlen] = '\0';
	fprintf(stderr, "[syncHardLink] srcPath : %s\n", srcPath);
	fprintf(stderr, "[syncHardLink] targetPath : %s\n", targetPath);
	if(link(targetPath, srcPath)){
		fprintf(stderr, "[syncHardLink] link failed.\n");
	}
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
	header.res.datalen = 0;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	send_message(conn_fd, &header, sizeof(header));
	return;
}

int syncAttrib(char *pathTmp, struct stat statBuf, struct stat metaBuf){
	if(S_ISLNK(metaBuf.st_mode)){
		struct timeval tvp[2];
		tvp[0].tv_sec = metaBuf.st_atime;
		tvp[1].tv_sec = metaBuf.st_mtime;
		tvp[0].tv_usec = tvp[1].tv_usec = 0;
		lutimes(pathTmp, tvp);
		return 1;
	}
	int syncFlag = 0;
	if (statBuf.st_mtime != metaBuf.st_mtime||
			statBuf.st_atime != metaBuf.st_atime){
		fprintf(stderr, "[syncAttrib] time different\n");
		struct utimbuf ubuf;
		memcpy(&ubuf.actime, &metaBuf.st_atime, sizeof(time_t)); 
		memcpy(&ubuf.modtime, &metaBuf.st_mtime, sizeof(time_t)); 
		if(utime(pathTmp, &ubuf) == -1){
			fprintf(stderr, "[syncAttrib] utime() failed.  Reason: %s\n", strerror(errno));
			syncFlag = 0;
		}
		else{
			syncFlag = 1;
		}
	}
	if (statBuf.st_mode != metaBuf.st_mode){
		fprintf(stderr, "[syncAttrib] mode different\n");
		if(chmod(pathTmp, metaBuf.st_mode) < 0){
			perror("[syncAttrib] mode change failed.\n");
			syncFlag = 0;
		}else{
			syncFlag = 1;
		}
	}
	return syncFlag;
}

void create(char *pathTmp, struct stat stat, int *order){
	if(S_ISDIR(stat.st_mode)){
		printf("%s is a directory\n", pathTmp);
		mkdir(pathTmp, DIR_S_FLAG);
		*order = 1;
	}
	else if(S_ISLNK(stat.st_mode)){
		printf("%s is a soft link\n", pathTmp);
		*order = 2;
	}
	else if(S_ISREG(stat.st_mode)){
		printf("%s is a regular file\n", pathTmp);
		printf("file size : %d\n", stat.st_size);
		FILE *wfp = fopen(pathTmp, "w");
		fclose(wfp);
		*order = 2;
	}
	else{
		printf("%s unknown\n", pathTmp);
		*order = 1;
	}
}

static void syncFile(char *pathTmp, csiebox_server* server, int conn_fd, struct stat metaBuf){
	csiebox_protocol_file file;
	if(!recv_message(conn_fd, &file, sizeof(file))){
		fprintf(stderr, "[syncFile] recv file length failed.\n");
		exit(1);
	}
	fprintf(stderr, "[syncFile] datalen : %d\n", file.message.body.datalen);
	if(file.message.body.datalen == 0){
		return;
	}
	char contentTmp[MAXCONTENT];
	if(!recv_message(conn_fd, contentTmp, file.message.body.datalen)){
		fprintf(stderr, "[syncFile] recv file data failed.\n");
		exit(1);
	}
	contentTmp[file.message.body.datalen] = '\0';
	if(S_ISLNK(metaBuf.st_mode)){
		symlink(contentTmp, pathTmp);
	}
	else{
		int fd = open(pathTmp, O_WRONLY);
		if (fd < 0){
			fprintf(stderr, "[syncFile] open file %s failed.\n", pathTmp);	
			exit(1);
		}
		if (write(fd, contentTmp, file.message.body.datalen) <= 0){
			fprintf(stderr, "[syncFile] write data into file failed.\n");
			exit(1);
		}
		close(fd);
	}
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
	header.res.datalen = 0;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	header.res.client_id = server->client[conn_fd]->conn_fd;
	send_message(conn_fd, &header, sizeof(header));
}

static void reClientMeta(char *pathTmp, struct stat statbuf, 
					csiebox_server *server, int conn_fd, fd_set *master, int fdmax){
	for(int i = 0; i <= fdmax; i++){
		if (server->client[i] != NULL){
			if (!strcmp(server->client[i]->account.user,
				    server->client[conn_fd]->account.user) && conn_fd != i){
				fprintf(stderr, "======reClientMeta======conn_fd : %d\n", conn_fd);
				reSyncMeta(pathTmp, statbuf, server, i);
				reSyncEnd(server, i);
//static void handle_request(csiebox_server* server, int conn_fd, fd_set *master, int fdmax);
				handle_request(server, i, master, fdmax);
			}
		}
	}
}

static void syncMeta(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta,
								fd_set *master, int fdmax) {
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	header.res.datalen = 0;
	char pathTmp[MAXLEN];
	sprintf(pathTmp, "%s/%s", server->arg.path, server->client[conn_fd]->account.user);
	char getPath[MAXLEN];
	
	int originalLen = strlen(pathTmp);
	fprintf(stderr, "[syncMeta] pathlen : %d\n", meta->message.body.pathlen);
	if(recv_message(conn_fd, &pathTmp[originalLen], meta->message.body.pathlen) == 0){
		fprintf(stderr, "meta recv file error\n");
		exit(1);
	}	
	pathTmp[originalLen+meta->message.body.pathlen] = '\0';
	printf("path got from client : %s\n", pathTmp);
	struct stat statbuf;
	int order = 0;
	if(lstat(pathTmp, &statbuf) < 0){
		create(pathTmp, meta->message.body.stat, &order);
	}
	else{
		if (S_ISREG(statbuf.st_mode)){
			char contentTmp[MD5_DIGEST_LENGTH];
			md5_file(pathTmp, contentTmp);
			if(strncmp(contentTmp, meta->message.body.hash, MD5_DIGEST_LENGTH) == 0){
				fprintf(stderr, "meta->message.body.hash %s the same\n", meta->message.body.hash);
				//==========
				// sync meta
				//==========
				order = 1;
			}
			else{
				fprintf(stderr, "meta->message.body.hash %s different from contentTmp %s\n"
						, meta->message.body.hash, contentTmp);
				order = 2;
			}
		}
		else{
				//==========
				// sync meta
				//==========
			order = 1;
		}
	}
	int syncFlag = 0;
	switch(order){
	case 0:
		header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
		break;
	case 1:
		syncFlag = syncAttrib(pathTmp, statbuf, meta->message.body.stat);
		header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
		break;
	case 2:
		header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
		break;
	}
	header.res.client_id = server->client[conn_fd]->conn_fd;
	send_message(conn_fd, &header, sizeof(header));
	fprintf(stderr, "[syncMeta] send success\n");
	if(header.res.status == CSIEBOX_PROTOCOL_STATUS_MORE){
		syncFile(pathTmp, server, conn_fd, meta->message.body.stat);
		syncAttrib(pathTmp, statbuf, meta->message.body.stat);
	}
//static int reSyncMeta(char *pathTmp, struct stat statBuf, csiebox_server *server, int conn_fd);
	if (order == 2 || syncFlag){
		reClientMeta(pathTmp, meta->message.body.stat, server, conn_fd, master, fdmax);
	}
}

static void logout(csiebox_server* server, int conn_fd) {
	free(server->client[conn_fd]);
	server->client[conn_fd] = 0;
	close(conn_fd);
}

static char* get_user_homedir(
		csiebox_server* server, csiebox_client_info* info) {
	char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
	memset(ret, 0, PATH_MAX);
	sprintf(ret, "%s/%s", server->arg.path, info->account.user);
	return ret;
}

