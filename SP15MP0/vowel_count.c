#include <stdio.h>
#include <assert.h>
#define MAXLENGTH 1000010

int main(int argc, char *argv[]){
	char alphabet[MAXLENGTH];
	FILE *fin;
	FILE *fout;

	fin = fopen(argv[1], "r+");
	assert(fin != NULL);
	fout = fopen(argv[2], "w+");
	assert(fout != NULL);
	fgets(alphabet, MAXLENGTH-1, fin);
	int i;
	int count = 0;
	for(i = 0; alphabet[i] != '\0' && alphabet[i] != '\n'; i++){
		if(alphabet[i] == 'a' || alphabet[i] == 'e' || alphabet[i] == 'i' ||
		   alphabet[i] == 'o' || alphabet[i] == 'u' || alphabet[i] == 'A' || 
		   alphabet[i] == 'E' || alphabet[i] == 'I' || alphabet[i] == 'O' || alphabet[i] == 'U')
			count++;
	}
	fprintf(fout, "%d\n", count);
	fclose(fin);
	fclose(fout);
	return 0;
}
