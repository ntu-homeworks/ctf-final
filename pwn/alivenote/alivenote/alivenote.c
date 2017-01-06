#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

char *note[10];

void read_input(char *buf,unsigned int size){
    int ret ;
    ret = read(0,buf,size);
    if(ret <= 0){
        puts("read error");
        exit(1);
    }
    if(buf[ret-1] == '\n')
        buf[ret-1] = '\x00';
}

int read_int(){
	int ret ;
    char buf[16];
    unsigned choice ;
    ret = read(0,buf,15);
    if(ret <= 0){
        puts("read error");
        exit(1);
    }
    choice = atoi(buf);
    return choice;
}

int check(char *str){
	int i ;
	for(i = 0 ; i < strlen(str) ; i++){
		if(str[i] != 0x20 && !isalnum(str[i])){
			return 0;
		}
	}
	return 1;
}

void add_note(){
	int idx ;
	char buf[8];
	printf("Index :");
	idx = read_int();
	if(idx > 10){
		puts("Out of bound !!");
		exit(0);
	}else{
		printf("Name :");
		read_input(buf,8);
		if(check(buf)){
			note[idx] = strdup(buf);
			puts("Done !");
		}else{
			puts("It must be a alnum name !");
			exit(-1);
		}
	}
}

void del_note(){
	int idx ;
	printf("Index :");
	idx = read_int();
	if(idx > 10){
		puts("Out of bound !!");
		exit(0);
	}else{
		free(note[idx]);
		note[idx] = 0 ;
	}

}

void show_note(){
	int idx ;
	printf("Index :");
	idx = read_int();
	if(idx > 10){
		puts("Out of bound !!");
		exit(0);
	}else{
		if(note[idx])
			printf("Name : %s\n",note[idx]);
	}

}

void menu(){
	puts("-----------------------------------");
	puts("             AliveNote             ");	
	puts("-----------------------------------");
	puts(" 1. Add a name                     ");
	puts(" 2. show a name on the note        ");
	puts(" 3. delete a name int the note     ");
	puts(" 4. Exit                           ");
	puts("-----------------------------------");
	printf("Your choice :");


}


int main(){
	setvbuf(stdout,0,2,0);
	setvbuf(stdin,0,2,0);
	while(1){
		menu();
		switch(read_int()){
			case 1 :
				add_note();
				break ;
			case 2 :
				show_note();
				break ;
			case 3 :
				del_note();
				break ;
			case 4 :
				exit(0);
				break ;
			default :
				puts("Invalid choice");
				break ;

		}
	}
	return 0;
}
