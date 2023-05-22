#writeup
# Ducky3
+ Category: Rev
+ Difficulty: Medium
+ Points: 497
+ Solves: 14
***
##### Description
> Alright fine, I'll make my own keyboard layout...
***
##### Files
`inject.bin` - data
`payload.txt` - ASCII text
***
##### Solve
Initially, this challenge only provided another `inject.bin` file. As the description says, this file dosn't seem to match any language, and appears to be custom made. The challenge was later fixed to include `payload.txt`
`payload.txt`:
```
STRING abcdefghijklmnopqrstuvwxyz
STRING ABCDEFGHIJKLMNOPQRSTUVWXYZ
STRING 0123456789
STRING !@#$%^&*()-_
STRING
```

`payload.txt` seems to be part of the payload that was encoded into `inject.bin`. Looking into how the [DuckToolkit encoder](https://github.com/kevthehermit/DuckToolkit/blob/master/ducktoolkit/encoder.py) works reveals that 'STRING' will simply encode the following string in the payload. This tells us that first part of `inject.bin`  encodes the string `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_`

We can use this to figure out the keycodes and decode the rest of the file.

```python
fpath = './inject.bin'
ht = {}
keys = {}
keystr = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_'
#keys['{  0x65}'] = 'C'
#keys['{2 0x6}'] = '{'
#keys['{2 0x10}'] = '}'
  
# read in data from inject.bin
with open(fpath, 'rb') as file:
    data = file.read()
  
def read_keycode(data, datidx):
    keycode = ''
    if data[datidx+1] == 2: # determine shift modifier from second byte
        keycode = keycode + '{2 '
    else:
        keycode = keycode + '{  '
    keycode = keycode + hex(data[datidx]) + '}' # determine keycode from first byte
    return keycode
  
# iterate over keystring and map keycodes to chars
for stridx, c in enumerate(keystr):
    datidx = stridx * 2 # keycodes are 2 bytes
    keycode = read_keycode(data, datidx)

    # map keycode to key character
    if not (keycode in keys):
        keys[keycode] = keystr[stridx]
  
# iterate over data and print decoded keys
for datidx in range(0, len(data), 2):
    keycode = read_keycode(data, datidx)
    if keycode in keys:
        print(keys[keycode], end='')
    else:
        print(keycode, end='')
print()
```

Because the encodings for '{' and '}' were not given, we have to figure out their mappings. This is simple because they are the only two unmapped chars. The characters 'b' and 'C' also have the same keycode of 0x6500 for some reason but we can manually map these values by uncommenting the following lines.
```
#keys['{  0x65}'] = 'C'
#keys['{2 0x6}'] = '{'
#keys['{2 0x10}'] = '}'
```

This allows us to determine the flag.
`byuctf{1_h0p3_y0u_enj0yed-thi5_very_muCH}`