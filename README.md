### HashKit

This project provides a simple command-line tool for generating hash values of user input strings using basic hash algorithms such as [MD5](https://en.wikipedia.org/wiki/MD5#Pseudocode), [SHA1](https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode), [SHA256](https://en.wikipedia.org/wiki/SHA-2#Pseudocode), and SHA224. The implementation is based on the pseudocode from corresponding Wikipedia pages, making it straightforward to understand and modify, although not the most optimized solution.

#### Usage
```
$ make
$ ./hash "abc"

Message is: abc
MD5 digest: 900150983cd24fb0d6963f7d28e17f72
SHA1 digest: a9993e364706816aba3e25717850c26c9cd0d89d
SHA256 digest: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
SHA224 digest: 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7d2da082d

```

```
$ ./hash "The quick brown fox jumps over the lazy dog" 

Message is: The quick brown fox jumps over the lazy dog
MD5 digest: 9e107d9d372bb6826bd81d3542a419d6
SHA1 digest: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
SHA256 digest: d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
SHA224 digest: 730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525000f8bdb

```


