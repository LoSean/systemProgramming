minclude <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void){
	int pid;
	
	int i;
	scanf("%d", &i);
	while(i--){
		if((pid = fork()) == 0){
			exit(0);
		}
	}
	sleep(60);
	return 0;
}
