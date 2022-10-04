Compute a rainbowtable from a dictionary file.
Use it to break SHA1.

Dummies reductions to turn sha1 into SIZE long strings (SIZE can be modify)


## Prepare input file

Use 'rockyou.txt' for example : https://github.com/praetorian-inc/Hob0Rules/tree/master/wordlists

Require to use a clean passwords dictionary, with one word per line

`cat rockyou.txt | awk '{print $1}' > rockyou_clean.txt`


## Build

`gcc *.c -o rain -lssl -lcrypto`

Output is `rainbow.txt` file

## Generate rainbow table

`./main -r rockyou_clean.txt`

Read input file line by line, and compute :

word -> sha1(word) -> reduce1 -> sha1(reduce1) -> reduce2 -> sha1(reduce2) -> reduce3 -> sha1(reduce3)

Write in output file : `word sha1(reduce3)`


## Break a hash searching its pre-image into the rainbowtable

```
./rain -b 9ffacc297245101b0f8ab06691bd73581bd081d7
Pass found : ,_GFABT&
```

## For debugging, compute values from one word

```
./rain -o toto
toto 0b9c2625dc21ef05f6ad4ddf47c5f203837aa32c
,_GFABT& 9ffacc297245101b0f8ab06691bd73581bd081d7
_1J5f1<0 f0cfac582604a93fc872b1218a86bb177f7bf81c
oyG%l`-5 4f7382e4c4a4ca3098f7f96aeda0defd2f752991
```

Output is read as :
```
word sha1(word)
reduce1 sha1(reduce1)
reduce2 sha1(reduce2)
reduce3 sha1(reduce3)
```
