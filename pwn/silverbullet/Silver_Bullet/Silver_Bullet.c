#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define MAX 48
struct Bullet{
	char desc[MAX];
	size_t power ;
};

struct Werewolf{
	int hp ;
	char *name ;
};

int read_input(char *buf,unsigned int size){
    int ret ;
    ret = read(0,buf,size);
    if(ret <= 0){
        puts("read error");
        exit(1);
    }
    if(buf[ret-1] == '\n')
        buf[ret-1] = '\x00';
    return ret ;
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

void init_proc(){
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,2,0);
}


void menu(){
    puts("+++++++++++++++++++++++++++");
    puts("       Silver Bullet       ");
    puts("+++++++++++++++++++++++++++");
    puts(" 1. Create a Silver Bullet ");
    puts(" 2. Power up Silver Bullet ");
    puts(" 3. Beat the Werewolf      ");
    puts(" 4. Return                 ");
    puts("+++++++++++++++++++++++++++");
    printf("Your choice :");
}

int beat(struct Bullet *bullet,struct Werewolf *wolf){
	if(bullet->desc[0] == '\x00'){
		puts("You need create the bullet first !");
		return 0;
	}
	printf(">----------- Werewolf -----------<\n");
	printf(" + NAME : %s\n",wolf->name);
	printf(" + HP : %d\n",wolf->hp);
	printf(">--------------------------------<\n");
	printf("Try to beat it .....\n");
	usleep(1000000);
	wolf->hp -= bullet->power ;
	if(wolf->hp > 0){
		puts("Sorry ... It still alive !!");
		return 0;
	}else{
		puts("Oh ! You win !!");
		return 1;
	}	
}


void create_bullet(struct Bullet *bullet){
	size_t power = 0 ;
	if(bullet->desc[0] != '\x00'){
		puts("You have been created the Bullet !");
		return ;
	}
	printf("Give me your description of bullet :");
	read_input(bullet->desc,MAX);
	power = strlen(bullet->desc);
	printf("Your power is : %u\n",power);
	bullet->power = power;
	puts("Good luck !!");
	return ;	
}

void power_up(struct Bullet *bullet){
	size_t power = 0;
	char buf[MAX];
	memset(buf,0,MAX);
	if(bullet->desc[0] == '\x00'){
		puts("You need create the bullet first !");
		return ;
	}
	if(bullet->power < MAX){
		printf("Give me your another description of bullet :");
		read_input(buf,MAX - bullet->power);
		strncat(bullet->desc,buf,MAX - bullet->power);
		power = strlen(buf) + bullet->power;
		printf("Your new power is : %u\n",power);
		bullet->power = power;
		puts("Enjoy it !");
	}else{
		puts("You can't power up any more !");		
	}
	return;
}


int main(){
    init_proc();
	struct Bullet rye ;
	struct Werewolf gin ;
	rye.power = 0 ;
	memset(rye.desc,0,MAX);
	gin.hp = 0x7fffffff ;
	gin.name = "Gin";	
    while(1){
        menu();
        switch(read_int()){
            case 1:
				create_bullet(&rye);
                break;
            case 2:
				power_up(&rye);
                break;
			case 3:
				if(beat(&rye,&gin)){
					return 0;
				}else{
					puts("Give me more power !!");
				}
				break;
			case 4:
				puts("Don't give up !");
                exit(0);
            default :
                puts("Invalid choice");
                break;
        }

    }
}
