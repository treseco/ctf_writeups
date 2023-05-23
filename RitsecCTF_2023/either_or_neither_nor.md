
#writeup
# Either or Neither nor
+ Category: crypto
+ Points: 100
***
##### Files
`chal.py` - Python script, ASCII text executable
***
##### Solve
The contents of chal.py tell us that the flag has been xored with a key and we only have the resulting encrypted flag.

```python
#! /usr/bin/env python 

flag = "XXXXXXXXXXXXXXXXXXXXX" 
enc_flag = [91,241,101,166,85,192,87,188,110,164,99,152,98,252,34,152,117,164,99,162,107]

key = [0, 0, 0, 0]
KEY_LEN = 4

# Encrypt the flag 
for idx, c in enumerate(flag): 
	enc_flag = ord(c) ^ key[idx % len(key)]
```

The xor operation has properties that make it simple to reverse. If `a ^ b = c` then `c ^ b = a`. Because we have the encrypted flag, and the encrypted bytes are equal to `f ^ k` where `f` and `k` are the flag bytes and the key bytes respectively, we can figure out bytes of the flag from bytes of the key and vice versa. Because we know the flag format is 'MetaCTF{}', we can find the key by individually xoring the first four bytes of the encrypted flag with the known first four bytes of the flag 'Meta'.

```python
# encrypted flag
enc_flag = [91,241,101,166,85,192,87,188,110,164,99,152,98,252,34,152,117,164,99,162,107]
key = [0, 0, 0, 0] 

# calculate key from enc_flag and known start of flag
key[0] = enc_flag[0] ^ ord('M')
key[1] = enc_flag[1] ^ ord('e')
key[2] = enc_flag[2] ^ ord('t')
key[3] = enc_flag[3] ^ ord('a')

# print decrypted flag
for idx, c in enumerate(enc_flag):
    print(chr(c ^ key[idx % len(key)]), end='')
print()
```

Flag: `MetaCTF{x0r_th3_c0re}`