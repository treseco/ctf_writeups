#writeup
# Ducky1
+ Category: Rev
+ Difficulty: Easy
+ Points: 100
+ Solves: 185
***
##### Description
> I recently got ahold of a Rubber Ducky, and have started automating ALL of my work tasks with it! You should check it out!
***
##### Files
`inject.bin` - data
***
##### Solve
The contents of `inject.bin` dosn't give us much information.
```
$ xxd inject.bin
00000000: 00ff 00ff 00ff 00ff 00ff 00ff 00ff 00ff  ................
	...
00000350: 00ff 00ff 00ff 00ff 00ff 00ff 00ff 005f  ..............._
00000360: 0500 1c00 1800 0600 1700 0900 2f02 1700  ............/...
00000370: 0b00 0c00 1600 2d02 1a00 0400 1600 2d02  ......-.......-.
00000380: 0d00 1800 1600 1700 2d02 0400 1100 2d02  ........-.....-.
00000390: 0c00 1100 1700 1500 1200 2d02 0400 0f00  ..........-.....
000003a0: 1500 0c00 0a00 0b00 1700 3802 3802 3002  ..........8.8.0.
```
The description tells us that this file is a "Rubber Ducky", and resarching this tells us that a Rubber Ducky is keyboard device that appears like a USB drive and sends a keystroke payload when pluged into a computer. Further research shows some tools that can be used to encode and decode these rubber ducky payloads, such as [DuckToolkit](https://github.com/kevthehermit/DuckToolkit). Using Ducktoolkit we can decode `inject.bin`.
```
$ python3 ducktools.py -d -l us ../inject.bin /dev/stdout
[+] Reading Duck Bin file
  [-] Decoding file
  [-] Writing ducky text to /dev/stdout
DELAY
byuctf{this_was_just_an_intro_alright??}[+] Process Complete
```
After decoding we get the flag. 
`byuctf{this_was_just_an_intro_alright??}`