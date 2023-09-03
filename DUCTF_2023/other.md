#writeup
# All Fathers Wisdom
+ Author: Pix
+ Category: rev
+ Difficulty: beginner
+ Points: 100
+ Solves: 270
***
##### Description
> We found this binary in the backroom, its been marked as "The All Fathers Wisdom" - See hex for further details. Not sure if its just old and hex should be text, or they mean the literal hex.
> 
> Anyway can you get this 'wisdom' out of the binary for us?
***
##### Files
`the-all-fathers-wisdom` - ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=01eec917a381d4efe62ed137f1349127f4faeeaa, for GNU/Linux 4.4.0, not stripped
***
##### Solve
The given file still includes the function names, so when we decompile it doesn't take long to find the function `main.print_flag()`:

``` c
void main.print_flag(undefined8 flag) {
  uint xor_res;
  undefined local_228 [16];
  undefined local_218 [16];
  undefined local_208 [16];
  long i;
  undefined8 *end;
  long bound;
  undefined8 local_1d8;
  
	...
 
  undefined8 local_8;
  undefined8 *end_ptr;
  long j;
  local_8 = 0x75;
  local_10 = 0x26;

	...  
 
  local_1d0 = 0x25;
  local_1d8 = 0x25;
  end = &local_1d8;
  bound = 59;
  for (i = 0; end_ptr = end, j = i, i < bound; i = i + 1) {
    runtime.bounds_check_error();
    xor_res = *(uint *)(end_ptr + j) ^ 0x11;
    local_228 = CONCAT88(0x4200000000000001,&xor_res);
    local_218 = CONCAT88(0x4200000000000001,&xor_res);
    local_208 = CONCAT88(1,local_218);
    fmt.printf("%c",2,local_218,1,flag);
  }
  return;
}
```

This function has many local variables that are assigned values. The for loop interates over the values, xors them with `0x11`, then prints them. We can can copy these values into a python script to compute the xor and print the flag.

``` python
# byte values in the local vars in main.print_flag() from ghidra
bytes=b'\x75\x26\x31\x22\x25\x31\x77\x24\x31\x25\x26\x31\x21\x22\x31\x74\x25\x31\x75\x23\x31\x22\x24\x31\x20\x22\x31\x77\x24\x31\x74\x27\x31\x20\x22\x31\x25\x27\x31\x77\x25\x31\x73\x26\x31\x27\x25\x31\x25\x24\x31\x22\x25\x31\x24\x24\x31\x25\x25'

decode = ""

# xor each byte and append it to decode. ignore spaces.
for b in bytes:
    if b != 49:
        decode += chr(b ^ 17)

# reverse the string. the program loops opposite to how we copied the data
decode = decode[-1:: -1]

# convert the decoded hex codes into ascii and print
for i in range(0, len(decode), 2):
    print(chr(int(decode[i:i+2], 16)), end='')
print()
```

`DUCTF{Od1n_1S-N0t_C}`

***
# Monke Bars
+ Author: ghostccamm
+ Category: osint
+ Difficulty: easy
+ Points: 100
+ Solves: 281
***
##### Description
> I will be dropping my new track **monke bars** soon! But I suck at rap and don't want to share it...
 >
> _Can you find the song?_
> 
> NOTE: Flag is in the format `DUCTF{...}` with no spaces and all lowercase between the `{}` characters. e.g. DUCTF{icannotrap}
***
##### Solve
The description tells us we need to find a song **monke bars**, and that the artist is not so good. A search on [Soundcloud](https://soundcloud.com/mc-fat-monke/monke-bars) for "monke bars" yields a song were the artist has left the comment:
`D-U-C-T-F left curly bracket smack it hack it drop that packet crack this track right curly bracket`. From this we can get the flag.

`DUCTF{smackithackitdropthatpacketcrackthistrack}`
***
# My First C Program
+ Author: Pix
+ Category: misc
+ Difficulty: easy
+ Points: 100 
+ Solves: 315
***
##### Description
> I decided to finally sit down and learn C, and I don't know what all the fuss is about this language it writes like a _**dream**_!
> 
> Here is my first challenge in C! Its really easy after you install the C installer installer, after that you just run it and you're free to fly away with the flag like a _**berd**_!

***
##### Files
`my_first_c_prog.c` - ASCII text
***
##### Solve
`my_first_c_prog.c` contains a poorly written program in c. The program first sets the values of some variables and then prints out the flag by combining the values of the variables in the following function:

``` c
   union print_flag(end, middle, secondmiddle, start, realstart) => {
print("The flag is:")!
print("DUCTF{${start}_${realstart}_${end}_${secondmiddle}_1s_${middle}_C}")!!!
   }

...

// Now to print the flag for the CTF!!
print_flag(thank, vars[-1], end, heck_eight, ntino)
```

For each argument to the `print_flag` function we can determine its value by interpreting and correcting the rest of the program. 

`DUCTF{I_D0nT_Th1nk_th15_1s_R34L_C}`
