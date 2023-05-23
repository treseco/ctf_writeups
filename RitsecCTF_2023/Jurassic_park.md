#writeup
# Jurassic park
+ Category: Rev
+ Points: 294
***
##### Files
`JuarrasicPark` - JurassicPark: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=4XMyVkn0sTek7nw8EEYU/QdfCrifAK-NMKTlAgud5/tWG5xm3UkP6nAyK9dh6I/QDTAn6gKrQy1Vt4Cl8mo, with debug_info, not stripped
***
##### Solve
I was not the first on my team to solve this challenge, but didn't notice until I had solved it. I feel it is still worth documenting this method of extracting a file from memory with pwndbg.

In `main` we find a call to `embed.FS.ReadFile` being called on a file called  `flag.png`
```
│       ┌─> 0x0048e500      cmp   rsp, qword [r14 + 0x10]
│      ┌──< 0x0048e504      jbe   0x48e615
│      │╎   0x0048e50a      sub   rsp, 0x70
│      │╎   0x0048e50e      mov   qword [var_8h], rbp
│      │╎   0x0048e513      lea   rbp, [var_8h]
│      │╎   0x0048e518      mov   rax, qword obj.main.f
│      │╎   0x0048e51f      lea   rbx, str.flag.png            ; 0x4a828a 
│      │╎   0x0048e526      mov   ecx, 8                       ; int64_t arg_20h
│      │╎   0x0048e52b      call  sym.embed.FS.ReadFile
	...
```

running the executable with gdb we can step to the instruction right after the call to `ReadFile`. $rax now points to the start of the file but we don't know where it ends. The end can be found by searching for the 'IEND' string in memory which will mark the end of PNG files. `0x444e4549` are the bytes that we are looking for. 

```
pwndbg> hexdump $rax
+0000 0xc000070000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  │.PNG....│....IHDR│
+0010 0xc000070010  00 00 03 ba 00 00 00 f9  08 06 00 00 00 09 20 49  │........│.......I│
+0020 0xc000070020  32 00 00 2c ea 49 44 41  54 78 5e ed dd 07 d8 34  │2..,.IDA│Tx^....4│
+0030 0xc000070030  eb 59 17 f0 fb 04 10 01  41 10 42 87 f3 26 48 42  │.Y......│A.B..&HB│
pwndbg> find $rax, +0xffffffff, 0x444e4549
0xc000072d1b
warning: Unable to access 16000 bytes of target memory at 0xc003ffc71f, halting search.
1 pattern found.
pwndbg> dump binary memory dump.bin $rax 0xc000072d2b
pwndbg>
```

Dumping the memory from $rax to a bit past the 'IEND' string will give us the flag.png and the image contains the flag.

Flag: `RS{G0_3MB3D_TH3_FLAG}`
