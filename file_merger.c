#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <math.h>
#include <assert.h>
#define BUF_SIZE sizeof(char) * 100000010
//characters in one line <= 100,000,000
//the multiplication of length of file1 and file2 <= 10,000,000

int main(int argc, char *argv[]){
	FILE *input1 = fopen(argv[1], "r");
	assert(input1 != NULL);
	FILE *input2 = fopen(argv[2], "r");
	assert(input2 != NULL);
	
	int sizex = 0, sizey = 0;
	char *buf1 = (char *)malloc(BUF_SIZE), 
	     *buf2 = (char *)malloc(BUF_SIZE);
	while(fgets(buf1, BUF_SIZE, input1) != NULL){
		sizex++;
	}
	while(fgets(buf1, BUF_SIZE, input2) != NULL){
		sizey++;
	}

	int **table = (int **)malloc(sizeof(int *) * (sizex + 5) +
				     sizeof(int) * (sizex + 5) * (sizey + 5));
	int *tmp;
	int i, j;
	for(i = 0, tmp = (int *)(table + sizex + 5) ; i < sizex + 5; i++, tmp += sizey + 5)
		table[i] = tmp;

	fseek(input1, 0, SEEK_SET);
	fseek(input2, 0, SEEK_SET);
	for(i = 0; i < sizex + 1; i++){
		if(i > 0)
			fgets(buf1, BUF_SIZE, input1);
		fseek(input2, 0, SEEK_SET);
		for(j = 0; j < sizey + 1; j++){
			if(i == 0 || j == 0)
				table[i][j] = 0;
			else{
				fgets(buf2, BUF_SIZE, input2);
				if(strcmp(buf1, buf2) == 0)
					table[i][j] = -(abs(table[i-1][j-1]) + 1);
				else
					table[i][j] = (abs(table[i-1][j]) > abs(table[i][j-1]))?
						      abs(table[i-1][j]) : abs(table[i][j-1]);
			}
		}
	}

	int startx = sizex, starty = sizey;
	int trail[10000][2] = {{0}, {0}};
	int count = 0;
	while(startx != 0 && starty != 0){
		if(starty > 0 && table[startx][starty] >= 0 &&
		   table[startx][starty] == abs(table[startx][starty-1]))
			starty--;
		else if(startx > 0 && table[startx][starty] >= 0 &&
			table[startx][starty] == abs(table[startx-1][starty]))
			startx--;
		else if(table[startx][starty] < 0){
			if((startx == sizex && starty == sizey) || 
			   (startx == 1 && starty == 1)){
				trail[count][0] = startx;
				trail[count][1] = starty;
				count++;
			}
			else if(table[startx-1][starty-1] + 1 <= 0 ||
				table[startx+1][starty+1] < 0){
				trail[count][0] = startx;
				trail[count][1] = starty;
				count++;
			}
			startx--; starty--;
		}	
	}
	
	FILE *output = fopen(argv[3], "w+");
	assert(output != NULL);
	fseek(input1, 0, SEEK_SET);
	fseek(input2, 0, SEEK_SET);
	
	startx = starty = 1;
	i = count - 1;
	while(startx < sizex + 1 || starty < sizey + 1){
		if(i >= 0 && startx == trail[i][0] && starty == trail[i][1]){
			fgets(buf1, BUF_SIZE, input1);
			fgets(buf1, BUF_SIZE, input2);
			fputs(buf1, output);
			startx++; starty++; i--;
		}
		else if(i >= 0){
			fprintf(output, ">>>>>>>>>> %s\n", basename(argv[1]));
			while(startx < trail[i][0]){
				fgets(buf1, BUF_SIZE, input1);
				fputs(buf1, output);
				startx++;
			}
			fprintf(output, "========== %s\n", basename(argv[2]));
			while(starty < trail[i][1]){
				fgets(buf1, BUF_SIZE, input2);
				fputs(buf1, output);
				starty++;
			}
			fprintf(output, "<<<<<<<<<<\n");
		}
		else{
			fprintf(output, ">>>>>>>>>> %s\n", basename(argv[1]));
			while(fgets(buf1, BUF_SIZE, input1) != NULL){
				fputs(buf1, output);
				startx++;
			}
			fprintf(output, "========== %s\n", basename(argv[2]));
			while(fgets(buf1, BUF_SIZE, input2) != NULL){
				fputs(buf1, output);
				starty++;
			}
			fprintf(output, "<<<<<<<<<<\n");
		}
	}
	fclose(input1);
	fclose(input2);
	fclose(output);
	return 0;
}
