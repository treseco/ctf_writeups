#writeup
# Masked Squares Flag Checker
+ Author: joseph
+ Category: rev
+ Difficulty: easy
+ Points: 218
+ Solves: 62
***
##### Description
> This program checks the flag based on some simple arithmetic operations.
***
##### Files
`ms_flag_checker` - ms_flag_checker: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a8e81b5edf26d75633d7f857771172e81689a563, for GNU/Linux 4.4.0, stripped
***
##### Solve
Begin by decompiling main and cleaning up the code.

```c
undefined8 main(void) {
  long mask_ptr;
  byte *mask_info;
  int *sum_target_ptr;
  int masked_sum;
  int flag_ints [36];
  char buf [40];

	...
	//prompt for flag, read in flag
	//convert flag chars to ints and store in flag_ints[36]
	...

  mask_info = MASK_INFO_BEGIN;
  sum_target_ptr = TARGET_SUMS_BEGIN;
  do {
    mask_ptr = make_mask((byte *)mask_info);
    masked_sum = sum_with_mask(flag_ints,mask_ptr);
    if (*sum_target_ptr != masked_sum) {
      puts("Incorrect!");
      exit(-1);
    }
    mask_info = mask_info[1];
    sum_target_ptr = sum_target_ptr + 1;
  } while (mask_info != (byte (*) [24])&MASK_INFO_END);
  puts("Correct!");
}
```

The `main()` function of the binary gives us a clear understanding of what this program does.
We just need to pass the check in every loop iteration. The output of the function we will call `sum_with_mask()` needs to match some value stored in the program data. We can see what `sum_with_mask()` does.

``` c
int sum_with_mask(int *flag_ints,long mask_ptr) {
  long idx;
  int sum;
  long row_end;
  row_end = 24;
  sum = 0;
  do {
    idx = row_end + -24;
    do {
      if (*(int *)(mask_ptr + idx) != 0) {
        sum = sum + *(int *)((long)flag_ints + idx);
      }
      idx = idx + 4;
    } while (idx != row_end);
    row_end = row_end + 24;
  } while (row_end != 168);
  return sum;
}
```

This function simply calculates the sum of all elements of `flag_ints` where the corresponding element in the mask is non-zero. We know that the return value of this function is what is checked in the flag check, and the desired sum is stored in the program data. Using this information we can get the flag knowing what subsets of flag characters sum to what value. We just need all the different subsets and with the correct sums. In order to find the subsets, we first need the masks, so we need to look at `make_mask()`.

``` c
void make_mask(byte *mask_info) {
  void *mask_ptr;
  int iterations;
  int offset;
  int col;
  int row;
  int byte_val;
  byte *next_byte;
  bool byte_lte_0;
  byte mask_byte;
  mask_ptr = malloc(144);
  mask_byte = *mask_info;
  if (mask_byte != 0) {
    next_byte = mask_info + 1;
    row = 0;
    col = 0;
    do {
      byte_val = (int)(char)mask_byte;
      byte_lte_0 = byte_val < 1;
      if (byte_lte_0) {
        byte_val = -byte_val;
      }
      iterations = 0;
      offset = col;
      do {
        col = offset + 1;
        *(uint *)((long)mask_ptr + ((long)offset + (long)row * 6) * 4) = (uint)!byte_lte_0;
        if (col == 6) {
          row = row + 1;
          col = 0;
        }
        iterations = iterations + 1;
        offset = col;
      } while (byte_val != iterations);
      mask_byte = *next_byte;
      next_byte = next_byte + 1;
    } while (mask_byte != 0);
  }
  return;
}
```

 This function essentially allocates space for a mask on the heap, then reads bytes from `mask_info` one by one. Each byte is interpreted as two's complement. The absolute value of the byte determines how many elements to add to the mask. The sign of the byte determines if those elements are 1 or 0, 1 for positive, 0 for negative. Now that we have this figured out, we can get all the masks from the mask info in the program data.

``` python
from z3 import *
  
# data from ghidra @00104060. array of ints that the sum of the flag chars
# is checked against after being masked.
target_sums_bytes = b'\xa1\x05\x00\x00\xfb\x07\x00\x00\xeb\x04\x00\x00\xef\x07\x00\x00\x07\x07\x00\x00\xea\x02\x00\x00\x37\x00\x00\x00\xaa\x05\x00\x00\xcd\x05\x00\x00\x52\x05\x00\x00\x63\x02\x00\x00\x22\x05\x00\x00\x66\x01\x00\x00\x2a\x07\x00\x00\xdc\x05\x00\x00\x4b\x05\x00\x00\xdb\x07\x00\x00\xc6\x07\x00\x00\x93\x07\x00\x00\xc6\x07\x00\x00\x16\x01\x00\x00\x43\x07\x00\x00\x3f\x08\x00\x00\xe6\x05\x00\x00\x78\x03\x00\x00\xc8\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
  
# data from ghidra @001040e0. array of arrays of bytes used to generate masks
mask_info = b'\xfb\x01\xfe\x01\xff\x03\xfd\x02\xff\x01\xff\x01\xff\x01\xff\x02\xfd\x02\xfe\x02\x00\x00\x00\x00\xff\x01\xfd\x02\xfd\x02\xff\x01\xfe\x03\xff\x01\xff\x07\xff\x03\xff\x02\x00\x00\x00\x00\x00\x00\xff\x01\xff\x01\xff\x02\xff\x01\xfa\x01\xff\x01\xfe\x01\xff\x01\xff\x01\xfc\x03\xff\x01\xfe\x00\x02\xff\x05\xfd\x03\xff\x04\xff\x02\xff\x05\xfd\x02\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x01\xfd\x01\xff\x01\xfe\x01\xff\x03\xff\x01\xff\x01\xfe\x05\xff\x04\xff\x01\xfd\x00\x00\x00\x01\xfe\x02\xf8\x01\xf9\x02\xff\x01\xfd\x01\xfe\x01\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xeb\x01\xf2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\x03\xfc\x04\xfb\x01\xfe\x01\xff\x01\xfe\x01\xfe\x01\xff\x04\xff\x00\x00\x00\x00\x00\x00\x00\xfc\x05\xfd\x01\xfb\x01\xfd\x01\xfe\x05\xfc\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x02\xfc\x01\xff\x04\xfd\x01\xfc\x01\xff\x02\xff\x01\xfd\x01\xff\x02\xfe\x00\x00\x00\x00\x00\xfe\x01\xf8\x01\xff\x01\xfd\x01\xff\x01\xf9\x01\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfe\x05\xff\x01\xf8\x03\xfe\x01\xfe\x01\xfd\x01\xfc\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfd\x01\xf7\x01\xfe\x01\xef\x01\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xfb\x04\xff\x01\xfe\x01\xff\x02\xfd\x03\xff\x01\xff\x03\xff\x02\xff\x00\x00\x00\x00\x00\x00\xfe\x02\xfd\x01\xff\x01\xff\x01\xff\x01\xf9\x01\xff\x06\xff\x03\xff\x01\xff\x00\x00\x00\x00\x00\x01\xfb\x01\xfe\x02\xff\x02\xff\x01\xff\x01\xfb\x01\xff\x01\xff\x05\xfc\x00\x00\x00\x00\x00\x00\x02\xfd\x01\xfb\x04\xfe\x03\xfe\x05\xff\x02\xff\x02\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x01\xfd\x01\xff\x02\xfe\x01\xff\x07\xfe\x03\xff\x04\xff\x01\xfe\x01\xff\x00\x00\x00\x00\x00\x02\xff\x01\xfe\x02\xff\x02\xfe\x05\xff\x01\xff\x02\xfd\x02\xff\x01\xfe\x02\xff\x01\x00\x00\x00\x01\xfd\x03\xff\x01\xfe\x01\xff\x06\xff\x01\xff\x02\xfe\x01\xff\x01\xff\x03\xff\x02\x00\x00\x00\xf7\x01\xf7\x01\xfb\x01\xf6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x02\xfe\x01\xff\x09\xff\x01\xff\x01\xf9\x02\xfe\x01\xfe\x01\x00\x00\x00\x00\x00\x00\x00\xff\x09\xff\x03\xff\x06\xff\x01\xff\x01\xfe\x01\xfd\x01\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\x01\xfd\x01\xff\x02\xfb\x06\xff\x02\xfe\x04\xff\x01\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\x01\xfc\x01\xff\x01\xfe\x01\xfd\x01\xfd\x01\xfd\x03\xfa\x01\xfe\x00\x00\x00\x00\x00\x00\x00\xf8\x04\xfe\x02\xff\x03\xfb\x01\xfe\x02\xff\x01\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
  
# convert bytes to integers
target_sums = [int.from_bytes(target_sums_bytes[i:i+4], 'little') for i in range(0, len(target_sums_bytes), 4)]
  
# process mask info to generate masks as done in func @00101189
# for each 2's complement byte in mask info, sign determines 1 or 0 in mask
# value determines how many 1s or 0s to add to append to the mask
masks = []
for i in range(0, len(mask_info), 24):
    mask = []
    for j in range(i, i+24):
        signed_val = mask_info[j] - 256 if mask_info[j] >= 128 else mask_info[j]
  
        if signed_val == 0:
            break
        elif signed_val <= 0:
            for k in range(0, abs(signed_val)):
                mask.append(0)
        else:
            for k in range(0, abs(signed_val)):
                mask.append(1)
    masks.append(mask)
  
s = Solver()
# 36 z3 vars, one for each char in the flag input
X = [ Int('x%s' % i) for i in range(36)]
# only int values of printable ascii
s.add([ And(X[i] >= 0, X[i] < 127) for i in range(36)])
# assume flag prefix
s.add(X[0]==68) #D
s.add(X[1]==85) #U
s.add(X[2]==67) #C
s.add(X[3]==84) #T
s.add(X[4]==70) #F
s.add(X[5]==123)#{
  
# add sum constraint for each mask based on required sum in target_sums and 
# summands specified by the mask
for i, m in enumerate(masks):
    s.add(target_sums[i]==Sum([ If(b!=0, X[j], 0) for j , b in enumerate(m)]))
  
print(s.check())
print(s.model())

# print flag
for c in [ s.model().evaluate(X[i]) for i in range(36) ] :
    print(chr(c.as_long()), end='')
print()
```

`DUCTF{ezzzpzzz_07bcda7bfe81faf43caa}`