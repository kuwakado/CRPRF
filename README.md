// https://cpp-learning.com/readme/
# Collision-Resistant and Pseudorandom Hashing Modes

We implemented benchmark software for two algorithms (KHC1 and KHC2) proposed in the following paper.

S. Hirose and H. Kuwakado,
"Collision-Resistant and Pseudorandom Hashing Modes of Compression Functions,"
Proceedings of 2025 Symposium on Cryptography and Information Security (SCIS2025),
2B4-2, 2025.

# Features

KHC1 and KHC2 were designed to calculate tags faster than HMAC for short messages.
Theoretically, the execution time of HMAC, KHC1, and KHC2 is roughly proportional to the number of SHA-256 compression functions, so KHC1 and KHC2 use the SHA-256 compression function less often than HMAC.

SHA-256 was used for the compression function and the SHA instruction (SHA-NI) was used to implement the SHA-256 compression function. Therefore, the length of a key is fixed at 256 bits. Although KHC1 and KHC2 can be applied to messages of arbitrary bit length, this implementation assumes that the message is an arbitrary sequence of bytes. This is because it is realistic to assume a byte sequence, and furthermore, it simplifies the padding process.


# Requirement

OS: Ubuntu 24.04.2 LTS x86_64
Compiler: gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0
Library: openssl (3.0.13-0ubuntu3.5)
CPU: AMD Ryzen 9 9950X, Intel Core i9-12900K, AMD Ryzen 9 5950X


# Installation

```shell-session
$ git clone https://github.com/hoge/~
$ cd crprf
$ make all 
$ make check (optional)
```
As a result, two executable files, 'crprf' and 'crprf_moc', are produced.

# Usage

To measure the execution time of HMAC of OpenSSL, HMAC, KHC1, and KHC2 for a randomly chosen 256-bit (32-byte) key and message ranging from 0 to 256 bytes in 32-byte increments, type:

```shell-session
$ ./crpf --maxByteLength=256 --repeatCount=129 --stepByte=32
```

In this example, each function was executed 129 times and the execution time was estimated. The execution time shown is the median of the execution time of 129 executions, and the unit is cycles.
For example, the result is displayed to the standard out as follows:

```batch
Bytes , OpenSSL-HMAC , HMAC , KHC1 , KHC2
0 , 3900 , 420 , 160 , 260
32 , 3860 , 420 , 160 , 260
64 , 3500 , 500 , 240 , 240
96 , 3500 , 500 , 240 , 240
128 , 3360 , 580 , 340 , 220
160 , 3340 , 580 , 340 , 340
192 , 3420 , 680 , 440 , 320
224 , 3420 , 680 , 420 , 420
256 , 3520 , 760 , 520 , 420
```

'crprf' is the executable file that runs HMAC of OpenSSL, custom HMAC, KHC1, and KHC2, measures their execution time, and displays them in CSV format.

Options of 'cprf' are shown below.

```batch
Usage: ./crprf [OPTIONS]
--help  print this help
--maxMessageByteLength=L  messages from 0 to L bytes (default: 256)
--repeatCount=N  repeat (odd) N times for obtain the median  (default: 129)
--stepByte=S  increase the message length by S bytes each (default: 32)
```

'crprf_moc' is also an executable file that displays the execution time when the essential processing of the SHA-256 compression function is omitted. 
Usage of crcprf_moc is the same as that of crprf.
By subtracting the latter from the former, the time required to execute the SHA-256 compression function can be calculated.


# Note

This package does not provide any executable files that allow users to give keys and messages and calculate tags. That is, it does not provide an executable file such as 'sha256sum' command.


# Authors

Hidenori Kuwakado and Shoichi Hirose


# License

[MIT license](https://opensource.org/license/mit)



