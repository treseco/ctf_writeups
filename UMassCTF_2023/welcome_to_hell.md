
# Welcome To Hell
+ Author: Battelle
+ Rev
+ 400 pts
***
##### Description
> Welcome to hell, where all it seems that you can do is try to exit, maybe there is a flag hidden somewhere in this mess
***
##### Files
`welcome_to_hell` - ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
***
##### Reversing
Opening `welcome_to_hell` in Ghidra shows a few functions. The only one that appears to do anything useful is `entry`, the first function in the binary. There are many other functions at higher addresses than entry, but they each just call syscall to exit the program. The return value of the *n*th exit function is *n*.
```c
void entry(void)
  
{
  int offset;
  char *bufptr;
  char buf [8];
  bool neg;
  syscall();       //read 3 bytes from stdin to buf
  offset = 0;
  neg = false;
  bufptr = buf + 1;
  if (buf[0] == '-') {
    neg = true;
    bufptr = buf + 2;
    buf[0] = buf[1];
  }
  
  do {
    offset = offset * 10 + (int)(char)(buf[0] + -0x30);
    buf[0] = *bufptr;
    if (buf[0] < '0') break;
    bufptr = bufptr + 1;
  } while (buf[0] < ':');
  if (neg) {
    offset = -offset;
  }
  
  (*(base + (int)((long)offset * 0x11)))(0,offset,(ulong)((long)offset * 0x11) >> 0x20);
  return;
}
```

`entry` provides some hints at what we should do. First, we see that we can provide some input that will jump to somewhere in the program. The address that we jump to is determined by an offset from `base`, which is the first exit function that follows `entry`. We could reverse the address calculations, or just test different offsets and see what exit code is returned.

```
$ ./welcome_to_hell
1
$ echo $?
1
$ ./welcome_to_hell
2
$ echo $?
2
$ ./welcome_to_hell
50
$ echo $?
50 
```

Clearly the offset is just the number of exit functions to jump over. However, everything below `base` exits the program and is not useful. Luckily we can see from `entry` that we can jump to negative offsets too. But where should we jump to? There are not many real options, and after looking around we realize that most of the data above `base` is just headers and such for the ELF. The most obvious choice is the suspicious looking junk found in the string table. Decompiling this data does appear to give us intructions but also some invalid instrucitons. There seems to be syscalls in this code, so instead of reversing the invalid instructions let's use `strace`.

```
$ echo '-30' | strace ./welcome_to_hell 
execve("./welcome_to_hell", ["./welcome_to_hell"], 0x7ffe934ba3c0 /* 10 vars */) = 0
read(0, "-30", 3)                       = 3
mmap(0x41414141000, 16384, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, 0, 0) = 0x41414141000
open("./welcome_to_hell", O_RDONLY)     = 3
lseek(3, 176, SEEK_SET)                 = 176
read(3, "!\340\214!\350\205ilii\1Ibhh\350]Mhhhh!\321\1\10\5\5\f\7\16\f"..., 12112) = 12112
write(1, "Welcome to the challenge!\n", 26Welcome to the challenge!
) = 26
write(1, "Enter the flag: ", 16Enter the flag: )        = 16
read(0, "\n", 48)                       = 1
exit(25)                                = ?
+++ exited with 25 +++
```

The programs first reads in the 3 byte offset, same as before. We pass in '-30' to jump to the beginning of the string table and run the instuctions there. The program then calls `mmap`, `open`, `lseek`, and `read` to read in unallocated data from the binary and map it into memory. Then we are welcomed to the challenge, and finally get the flag prompt. The program then quits, presumably because we didn't give the flag. Let's look with gdb.

```
 ► 0x4141414108f     syscall  <SYS_read>
        fd: 0x0 (/dev/pts/0)
        buf: 0x41414142fd0 ◂— xor esi, dword ptr [rbx] /* 0x3333333333333333 */
        nbytes: 0x30
   0x41414141091     mov    rdx, rax
   0x41414141094     mov    rdi, 0x19
   0x4141414109e     je     0x414141410a9                 <0x414141410a9>
   0x414141410a0     mov    rax, 0x3c
   0x414141410a7     syscall 
   0x414141410a9     nop
```

Eventually, we can the read syscall before the program exits. We can see that if read returns a length other than 0x19 then we call exit, otherwise we continue. We'll give it a 25 character sting and continue stepping.

```
   0x414141410a9    nop    
   0x414141410aa    lea    rsp, [rip + 9]
   0x414141410b1    mov    rax, 0xf
 ► 0x414141410b8    syscall  <SYS_rt_sigreturn>
   0x414141410ba    add    byte ptr [rax], al
   0x414141410bc    add    byte ptr [rax], al
   0x414141410be    add    byte ptr [rax], al
   0x414141410c0    add    byte ptr [rax], al
   0x414141410c2    add    byte ptr [rax], al
```

Ok now that the flag length is correct we are at the instuctions above, which points the stack pointer to the data after the syscall and calls `rt_sigreturn`. This is a function used to restore the process state after the program returns from handling a signal. Typically the state is stored on the stack before control is transfered to the kernel, and restored by sigreturn when the kernel is done. In this case there is no signal, and the program is using its own fabricated signal frame (the junk instructions after the syscall) to modify the process state. This is a pwn technique know as SROP.

```
 ► 0x414141411b2    add    r9, rcx
   0x414141411b5    mov    r10, qword ptr [r9 + 1]
   0x414141411b9    xor    rax, r8
   0x414141411bc    add    cl, 0xb
   0x414141411bf    shr    rax, cl
   0x414141411c2    cmp    al, r10b
   0x414141411c5    je     0x414141411c9                 <0x414141411c9>
   
   0x414141411c7    jmp    rdx
   
   0x414141411c9    nop    
   0x414141411ca    lea    rsp, [rip + 9]
   0x414141411d1    mov    rax, 0xf
   0x414141411d8    syscall
```

Each signal frame that is "restored" has the format above. `r10` is pointed to the next character in our flag. Some operations are perfomed on `rax`, but by the compare instruction it will be the correct flag character. At this point we can just contine stepping through, dumping `rax`, and setting `r10` to get the full flag.

```python
#!/usr/bin/python3
  
from pwn import *
  
p = process('./welcome_to_hell')
  
p.send(b'-30')
p.recvline()
p.recvuntil(b'flag: ')
p.send(b'UMASS{sr0p_n_r3v_is_h3ll}')
print(p.recvall())
```

Pwntools is usefull to test the flag we found by passing it to to program before it quits and without newlines.

```
$ ./heaven.py 
[+] Starting local process './welcome_to_hell': pid 1178
[+] Receiving all data: Done (25B)
[*] Stopped process './welcome_to_hell' (pid 1178)
b'UMASS{sr0p_n_r3v_is_h3ll}'
```

Nice. Overall this was a cool challenge. I certainly learned a lot about the ELF file format and especially UNIX signals. SROP is new to me so this was a neat chance to learn about how it works and how it can be used. 
