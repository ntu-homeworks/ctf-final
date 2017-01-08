#include <stdio.h>
#include <unistd.h>

int main(){
	char buf[8];
	read(0,buf,100);
	close(0);
	close(1);
	close(2);
}
