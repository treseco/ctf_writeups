#writeup
# Ducky2
+ Category: Rev
+ Difficulty: Medium
+ Points: 476
+ Solves: 36
***
##### Description
> Okay, turnsk out that wask too easy to decode. You skhoud definitely try thisk one now!
> (_Note - Ducky3 is unlocked after solving this challenge_)
***
##### Files
`inject.bin` - data
***
##### Solve
We are given a very similar file to `inject.bin` from ducky1. Let's try to decode this one with [DuckToolkit](https://github.com/kevthehermit/DuckToolkit) as well.
```
$ python3 ducktools.py -d -l us ../inject.bin /dev/stdout
[+] Reading Duck Bin file
  [-] Decoding file
  [-] Writing ducky text to /dev/stdout
DELAY
bzuctfmakesurezourkezboardissetupright|_}|"}|[+] Process Complete
```
Ok, that didn't seem to work but it does give us a hint by telling us to 'make sure your keyboard is set up right'. DuckToolkit does give us the option of decoding using different languages so this is something to try. We just need to determine what language this could be. 

Most characters seem to decode correctly, we can see that 'bzuctf' is probably supposed to be 'byuctf'. By compareing the data in `inject.bin` from ducky1 to the data in `inject.bin` from ducky2, we can determine what keycodes should print what characters. Using the language files in `DuckToolkit/ducktoolkit/languages` will be helpful for figuring out the keycodes.

> [!WARNING] 
> Installing DuckToolkit via pip will not include all of the language files in the git repo, so it is advised to install from git for this challenge.

ducky1 `inject.bin` with lang = 'us':
```
00000360: 0500 1c00 1800 0600 1700 0900 2f02  -> decodes to -> 'byuctf{'
          b    y    u    c    t    f    {
```

ducky2 `inject.bin` with lang = ?:
```
00000360: 0500 1d00 1800 0600 1700 0900 0505  -> decodes to -> 'bzuctf'
		  b    z(y) u    c    t    f    ({)
```

We can see that the language we need encodes '{' as '0505', so the correct language will have this line in the language file:
`"{":"05,00,05",`

It turns out there are two languages, Czech and Slovak, that have this property and decode the payload without issues.
```
$ python3 ducktools.py -d -l cz ../inject.bin /dev/stdout
[+] Reading Duck Bin file
  [-] Decoding file
  [-] Writing ducky text to /dev/stdout
DELAY
byuctf{makesureyourkeyboardissetupright'@&%(#@'!(#*$'}[+] Process Complete
$ python3 ducktools.py -d -l sk ../inject.bin /dev/stdout
[+] Reading Duck Bin file
  [-] Decoding file
  [-] Writing ducky text to /dev/stdout
DELAY
byuctf{makesureyourkeyboardissetupright)@&%(#@)!(#*$)}[+] Process Complete
```

Aside from the numerous intentional 'sk' typos in the challenge description, it is not obvious which flag is correct but trying both will reveal the correct flag.
`byuctf{makesureyourkeyboardissetupright)@&%(#@)!(#*$)}`