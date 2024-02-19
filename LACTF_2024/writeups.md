#writeup

# LACTF 2024
I was able to participate in LACTF this weekend with [WolvSec](https://wolvsec.org) and it was a lot of fun. We ended up placing 166th in the open division. These are my writeups for `glottem`, `the-secret-of-java-island` and `aplet321` reversing challenges.

## glottem
+ Category: Rev
+ Author: aplet123
+ Points: 455
+ Solves: 89
***
##### Description
> Haha glottem good!
>
> Note: The correct flag is 34 characters long.
***
##### Files
`glottem`: POSIX shell script, ASCII text executable, with very long lines
***
##### Solve

The provided shell script

```sh
#!/bin/sh
1<<4201337
1//1,"""
exit=process.exit;argv=process.argv.slice(1)/*
4201337
read -p "flag? " flag
node $0 "$flag" && python3 $0 "$flag" && echo correct || echo incorrect
1<<4201337
*///""";from sys import argv

#// e = a very large 3 dimentional matrix, removed for brevity

alpha="abcdefghijklmnopqrstuvwxyz_"
d=0;s=argv[1];1//1;"""
/*"""
#*/for (let i = 0; i < s.length; i ++) {/*
for i in range(6,len(s)-2):
    #*/d=(d*31+s.charCodeAt(i))%93097/*
    d+=e[i-6][alpha.index(s[i])][alpha.index(s[i+1])]#*/}
exit(+(d!=260,[d!=61343])[0])
4201337
```

The script is challenging to read but it essentially creates a file that is both valid python and javascript, and checks the flag input against both programs.
Here is the resulting python file without the javascript comments:

```python
e = [ ... ]
alpha="abcdefghijklmnopqrstuvwxyz_"
# argv1 is the user provided flag string
d=0; s=argv[1];for i in range(6, len(s)-2) :
    d+=e[i-6][alpha.index(s[i])][alpha.index(s[i+1])]
# d == 260 indicates the input flag passed the check
exit(d!=260)
```
and the javascript file:
```javascript
e = [ ... ]
alpha="abcdefghijklmnopqrstuvwxyz_"
d=0;s=argv[1];
for (let i = 0; i < s.length; i ++) {
  d = (d*31+s.charCodeAt(i)) % 93097
// d == 61343 indicates the input flag passed the check
process.exit(d!=61343) 
```
Each of these programs applies some constraints on the possible correct flags, and together they form a verifier. I spent some time trying to use an SMT solver to solve for the flag, but this approach proved challengeing. Because the flag charcters that we are solving for are used to index into `e`, we really want concrete values rather than symbolic ones. The real insight comes from realizing that all the elements in `e` fall between `10 <= x <=17`. Since we are given that the flag is 34 chars long, and the python program only checks the chars from index 6 to 34-2, we know it checks the 26 chars between the brackets. Each of these chars increments `d` by a minimum of 10 and the total must be 260, thus each iteration of the loop must result in some element of `e` with the value 10.
With the resulting strings that correctly produce the sum of 260, we can compute the same check done by the javascript program until we find one that passes both.

```python
e = [ ... ]
alpha = "abcdefghijklmnopqrstuvwxyz_"

# return all flag strings flag[idx:] with c at idx that result in all 10s
def find_tens(idx, c) :
    if (idx >= 26):
        return ['']
    good = []
    last = -1
    # assuming char c at flag[idx], find all indexes that produce a 10
    while(e[idx][alpha.index(c)][last+1:].count(10)) :
        found_ten = e[idx][alpha.index(c)].index(10, last+1)
        good.append(found_ten)
        last = found_ten
    if not good:
        return ['']
    else :
        ret = []
        # for all good indexes, get the letter producing said index
        # and recursivly call find_tens
        rec = [find_tens(idx+1, alpha[g]) for g in good]
        for x in rec :
            for y in x :
                # concat all valid recursive sequences with c
                ret.append(c+y)
        return ret
        
# helper for enumerating the missing char
def inc_miss(missing) :
    inc_idx = alpha.index(missing)+1
    if inc_idx is len(alpha) :
        return 'a'
    else :
        return alpha[inc_idx]

# do js program check, return d
def check_js(flag, missing) :
    d = 0
    for c in flag :
        d = (d * 31 + ord(c)) % 93097
    return d

for i, c in enumerate(alpha) :
    # find all strings that produce 10s, try starting will all chars in alpha
    for s in find_tens(0, c):
        if len(s) == 26 :
            # build a flag with each 10s string + flag format + last missing char
            missing = 'a'
            flag = "lactf{" + s + missing + '}'
            # check the potential flag with all alphabet chars as the missing char
            while(True) :
                score = check_js(flag, missing)
                if (score == 61343) :
                    print(flag)
                if(missing == '_') :
                    break
                missing = inc_miss(missing)
                flag = "lactf{" + s + missing + '}'
```

The solve script will take a second to run, and will return a few possible flags but only one isn't completly random.

`lactf{solve_one_get_two_free_deal}`

## the-secret-of-java-island
+ Category: Rev
+ Author: aplet123
+ Points: 312
+ Solves: 284
***
##### Description
> The Secret of Java Island is a 2024 point-and-click graphic adventure game developed and published by LA CTF Games. It takes place in a fictional version of Indonesia during the age of hacking. The player assumes the role of Benson Liu, a young man who dreams of becoming a hacker, and explores fictional flags while solving puzzles.
***
##### Files
`game.jar`: Java archive data (JAR) 
***
##### Solve
We are provide with a `jar` file that we can open with a tool like [decompiler.com](https://www.decompiler.com/). By looking at `JavaIsland.java` and running the file will show us that the program presents the user with a series of choices and will only print the flag when the correct sequence is executed. `JavaIsland.java` reveals that the target.

```java
case 3:
         if (!hasGlove) {
            story.setText("<html>You reach for the lever, plunging your hand into the thick veil of spider webs. While trying to pull the lever, you feel a sharp pain on your arm before your vision fades to black. Game over.</html>");
            button1.setText("I understand");
            button2.setText("I understand");
         } else {
            story.setText("<html>You reach for the lever, plunging your gloved hand into the thick veil of spider webs. The lever makes a loud creaking sound as you press it down, powering a large floodlight that lights up the entire room. When you look at your hand in the newfound light, you see several large spiders climbing on your glove. Startled, you shake the glove off and run to the other corner of the room, where you see a flag that must've been there the entire time.</html>");
            button1.setText("Read the flag");
            button2.setText("Read the flag");
         }
         break;
```

Reaching the target involves entering case 3 with the golve item. By investigating the `trasitionState` method we can learn how to manipulate the state in order to reach case 3. In this method we find that we need to pass a check when in state 4 or else the program will exit.

```java
      case 4:
         if (var0 == 0) {
            exploit = exploit + "d";
            story.setText("You clobbered the DOM. That was exploit #" + exploit.length() + ".");
         } else {
            exploit = exploit + "p";
            story.setText("You polluted the prototype. That was exploit #" + exploit.length() + ".");
         }

         if (exploit.length() == 8) {
            try {
               MessageDigest var1 = MessageDigest.getInstance("SHA-256");
               if (!Arrays.equals(var1.digest(exploit.getBytes("UTF-8")), new byte[]{69, 70, -81, -117, -10, 109, 15, 29, 19, 113, 61, -123, -39, 82, -11, -34, 104, -98, -111, 9, 43, 35, -19, 22, 52, -55, -124, -45, -72, -23, 96, -77})) {
                  state = 7;
               } else {
                  state = 6;
               }

               updateGame();
            } catch (Exception var2) {
               throw new RuntimeException(var2);
            }
         }

         return;
```
Here the user is asked to make a series of 8 choices, and the series of choices is translated to a string. The string is then hashed and the resulting digest is checked against the correct hash. If the hash does not match we are sent to state 7 and the program exits. Because the string is a combination of 'd's and 'p's, we can hash all the possible strings with `sha256` to find the correct sequence of choices.

```python
import hashlib

for v in range(0x00, 0x100):
    bits = [1 if v & (1 << (7-n)) else 0 for n in range(8)]
    bs = b''
    for bit in bits:
        if bit == 1:
            bs += b'p'
        else:
            bs += b'd'
    m = hashlib.sha256()
    m.update(bs)
    # check that hash matches first couple bytes in the correct hash
    if(m.hexdigest()[0:4] == '4546'):
        print(bs)
```

This script will yield the sequence: `dpddpdpp`. we can now run the game, run this series of exploits at the computer then pull the lever to see the flag.

`lactf{the_graphics_got_a_lot_worse_from_what_i_remembered}`

## aplet321
+ Category: Rev
+ Author: kaiphait
+ Points: 199
+ Solves: 445
***
##### Description
> Unlike Aplet123, Aplet321 might give you the flag if you beg him enough.
>
> `nc chall.lac.tf 31321`
***
##### Files
`aplet321`: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b6322155d8e3d5ecbc678a2697ccce38be0e7c10, for GNU/Linux 3.2.0, not stripped
***
##### Solve
We are given an ELF file, opening the `main` function with ghidra's decompiler yeilds:
```c
undefined8 main(void)
{
    // local declarations removed for brevity
        
    // [14] -r-x section size 553 named .text
    sym.imp.setbuf(_reloc.stdout, 0);
    sym.imp.puts("hi, i\'m aplet321. how can i help?");
    sym.imp.fgets(&var_238h, 0x200, _reloc.stdin);
    uVar2 = sym.imp.strlen(&var_238h);
    if (5 < uVar2) {
        iVar5 = 0;
        iVar6 = 0;
        piVar4 = &var_238h;
        do {
            iVar1 = sym.imp.strncmp(piVar4, "pretty", 6);
            iVar6 = iVar6 + (uint32_t)(iVar1 == 0);
            iVar1 = sym.imp.strncmp(piVar4, "please", 6);
            iVar5 = iVar5 + (uint32_t)(iVar1 == 0);
            piVar4 = (int64_t *)((int64_t)piVar4 + 1);
        } while (piVar4 != (int64_t *)((int64_t)&var_238h + (uint64_t)((int32_t)uVar2 - 6) + 1));
        if (iVar5 != 0) {
            iVar3 = sym.imp.strstr(&var_238h, "flag");
            if (iVar3 == 0) {
                sym.imp.puts("sorry, i didn\'t understand what you mean");
                return 0;
            }
            if ((iVar6 + iVar5 == 0x36) && (iVar6 - iVar5 == -0x18)) {
                sym.imp.puts("ok here\'s your flag");
                sym.imp.system("cat flag.txt");
                return 0;
            }
            sym.imp.puts("sorry, i\'m not allowed to do that");
            return 0;
        }
    }
    sym.imp.puts("so rude");
    return 0;
}
```
 
Here we can see that the program reads in some input and saves it to a buffer. We can also see the call to `system("cat flag.txt")` which is our target. We just need to find the input that results in the program reaching the target. To do this we can turn all the conditional checks into a system of equations. First the input must be longer than 5 characters, and needs to contain the word flag. Next, the words 'pretty' and 'please' need to show up at exactly 56 times, and 'please' needs to show up 24 times more than 'pretty'.

```
num_pretty + num_please = 56
num_please - num_pretty = 24

num_pretty = 15
num_please = 39
```

We can now craft our input and send it to the remote server.

```
$ python3 -c 'print("pretty " * 15 + "please " * 39 + "flag")' | nc chall.lac.tf 31321
hi, i'm aplet321. how can i help?
ok here's your flag
lactf{next_year_i'll_make_aplet456_hqp3c1a7bip5bmnc}
```

flag: `lactf{next_year_i'll_make_aplet456_hqp3c1a7bip5bmnc}`
