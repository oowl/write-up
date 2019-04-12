# otp

```
I made a skeleton interface for one time password authentication system.
I guess there are no mistakes.
could you take a look at it?

hint : not a race condition. do not bruteforce.

ssh otp@pwnable.kr -p2222 (pw:guest)
```
给出了源码
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char* argv[]){
	char fname[128];
	unsigned long long otp[2];

	if(argc!=2){
		printf("usage : ./otp [passcode]\n");
		return 0;
	}

	int fd = open("/dev/urandom", O_RDONLY);
	if(fd==-1) exit(-1);

	if(read(fd, otp, 16)!=16) exit(-1);
	close(fd);

	sprintf(fname, "/tmp/%llu", otp[0]);
	FILE* fp = fopen(fname, "w");
	if(fp==NULL){ exit(-1); }
	fwrite(&otp[1], 8, 1, fp);
	fclose(fp);

	printf("OTP generated.\n");

	unsigned long long passcode=0;
	FILE* fp2 = fopen(fname, "r");
	if(fp2==NULL){ exit(-1); }
	fread(&passcode, 8, 1, fp2);
	fclose(fp2);
	
	if(strtoul(argv[1], 0, 16) == passcode){
		printf("Congratz!\n");
		system("/bin/cat flag");
	}
	else{
		printf("OTP mismatch\n");
	}

	unlink(fname);
	return 0;
}
```

解法很巧妙.直接利用linux的限制特性
`unlimet -f 0`，限制文件文件创建大小为0，这样我们`fwrite`写出的东西就没有了，`fread`都出来的是`0`

```
>>> import os
>>> os.system('./otp 0')
```
这里使用`python shell`的原因大概是,防止无法创建文件而报错了.