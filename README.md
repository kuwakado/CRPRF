# Collision-Resistant and Pseudorandom Hashing Modes

This repository provides benchmark software for comparing HMAC with two algorithms (KHC1 and KHC2) proposed in the following paper.

S. Hirose and H. Kuwakado,
"Collision-Resistant and Pseudorandom Hashing Modes of Compression Functions,"
Proceedings of 2025 Symposium on Cryptography and Information Security (SCIS2025),
2B4-2, 2025.  
[https://www.iwsec.org/scis/2025/program.html](https://www.iwsec.org/scis/2025/program.html)

# Features

KHC1 and KHC2 were designed to calculate tags faster than HMAC for short messages.
Theoretically, the execution time of HMAC, KHC1, and KHC2 is roughly proportional to the number of SHA-256 compression functions, so KHC1 and KHC2 use the SHA-256 compression function less often than HMAC.

SHA-256 was used for the compression function and the SHA instruction (SHA-NI) was used to implement the SHA-256 compression function. Therefore, the length of a key is fixed at 256 bits. Although KHC1 and KHC2 can be applied to messages of arbitrary bit length, this implementation assumes that the message is an arbitrary sequence of bytes. This is because it is realistic to assume a byte sequence, and furthermore, it simplifies the padding process.


# Requirement (Development environment)

Distribution: Ubuntu 24.04.2 LTS x86_64  
OS: Linux 6.8.0
Compiler: gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0  
Library: openssl (3.0.13-0ubuntu3.5)  
CPU: AMD Ryzen 9 9950X, Intel Core i9-12900K, AMD Ryzen 9 5950X, AMD EPYC-Milan


# Installation

```shell-session
$ git clone https://github.com/kuwakado/CRPRF.git
$ cd CRPRF
$ make all 
```
When you run "make all", you'll get a lot of warnings, but that's ok.
As a result, three executable files, 'crprf', 'crprf_moc', and 'crprf_moc_sha256cf', are produced in the current directory.

# Usage

To measure the execution time of HMAC of OpenSSL, HMAC, KHC1, and KHC2 for a randomly chosen 256-bit (32-byte) key and message ranging from 0 to 256 bytes in 32-byte increments, type:

```shell-session
$ ./crprf --maxMessageByteLength=256 --repeatCount=129 --stepByte=32
```

In this example, each function was executed 129 times and the execution time was estimated. The execution time shown is the median of the execution time of 129 executions, and the unit is cycles.
For example, the result is displayed to the standard out as follows:

```batch
Bytes , OpenSSL-HMAC , HMAC , KHC1 , KHC2
0 , 3740 , 440 , 200 , 280
32 , 3360 , 440 , 180 , 280
64 , 3420 , 520 , 280 , 280
96 , 3380 , 520 , 280 , 260
128 , 3180 , 620 , 380 , 260
160 , 3180 , 620 , 360 , 360
192 , 3220 , 700 , 460 , 360
224 , 3200 , 700 , 460 , 460
256 , 3320 , 800 , 560 , 440
```

'crprf' is the executable file that runs HMAC of OpenSSL, custom HMAC, KHC1, and KHC2, measures their execution time, and displays them in CSV format. Options of 'cprf' are shown below.

```batch
Usage: ./crprf [options]
--help  print this help
--maxMessageByteLength=L  message length from 0 to L bytes (default: 256)
--repeatCount=N  repeat (odd) N times for obtaining the median  (default: 129)
--stepByte=S  increase the message length by S bytes each (default: 32)
```

'crprf_moc' is also an executable file that displays the execution time when the processing of HMAC, that of KHC1, and that of KHC2 are omitted. 
Note that the processing of OpenSSL HMAC is not omitted.
Subtracting the result of 'crprf_moc' from the result of 'crprf' gives the precise execution times of HMAC, KHC1, and KHC2 (i.e., excluding the time for measurement).
Usage of 'crcprf_moc' is the same as that of 'crprf'.

```shell-session
$ ./crprf_moc --maxMessageByteLength=256 --repeatCount=129 --stepByte=32
```
The result of the above command might look something like this:

```batch
Bytes , OpenSSL-HMAC , HMAC , KHC1 , KHC2
0 , 3660 , 80 , 80 , 80
32 , 3280 , 80 , 80 , 80
64 , 3340 , 80 , 80 , 80
96 , 3360 , 80 , 80 , 80
128 , 3120 , 80 , 80 , 80
160 , 3120 , 80 , 80 , 80
192 , 3180 , 80 , 80 , 80
224 , 3120 , 80 , 80 , 80
256 , 3200 , 80 , 80 , 80
```

Finally, 'crprf_moc_sha256cf' is an executable file that displays the execution time of HMAC, that of KHC1, and that of KHC2 excluding that of the SHA-256 compression function.
That is, the displayed time is approximately the sum of the time for padding and that for XORing constants.
Subtracting the result of 'crprf_moc_sha256cf' from the result of 'crprf' gives the precise times for spending the calculation of the compression funcion in HMAC, KHC1, and KHC2.
Usage of 'crcprf_moc_sha256cf' is the same as that of 'crprf'.
For example, type:

```shell-session
./crprf_moc_sha256cf --maxMessageByteLength=256 --repeatCount=129 --stepByte=32
```

Then, the following results are displayed.
Note that the time of OpenSSL HMAC includes the time of the compression function.
In other words, nothing has changed from the original OpenSSL HMAC.

```batch
Bytes , OpenSSL-HMAC , HMAC , KHC1 , KHC2
0 , 3420 , 160 , 100 , 100
32 , 3360 , 140 , 100 , 100
64 , 3380 , 140 , 100 , 100
96 , 3380 , 140 , 100 , 100
128 , 3080 , 140 , 100 , 100
160 , 3060 , 160 , 100 , 100
192 , 3160 , 160 , 100 , 100
224 , 4800 , 220 , 120 , 120
256 , 3220 , 160 , 100 , 100
```

In the three exmples above, the code of OpenSSL HMAC is identical.
However, the execution times are all different even if the message length is the same.
For example, when the message length is zero, they are 3740  [clocks], 3660 [clocks], and 3420 [clocks], respectively.
In my experience, the median execution times for Open SSL HMAC, as well as others, do not stabilize until after a significant number of iterations (--repeatCount option).


# Note

This package does not provide any executable files that allow users to give keys and messages and calculate tags. That is, it does not provide an executable file such as 'sha256sum' command.


# Authors

Hidenori Kuwakado

Shoichi Hirose gave me advice about the programs.


# License

[MIT license](https://opensource.org/license/mit)

Copyright 2025  Hidenori Kuwakado



