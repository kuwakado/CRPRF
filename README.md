# Collision-Resistant and Pseudorandom Hashing Modes

We implemented benchmark software for comparing HMAC with two algorithms (KHC1 and KHC2) proposed in the following paper.

S. Hirose and H. Kuwakado,
"Collision-Resistant and Pseudorandom Hashing Modes of Compression Functions,"
Proceedings of 2025 Symposium on Cryptography and Information Security (SCIS2025),
2B4-2, 2025.  
[https://www.iwsec.org/scis/2025/program.html](https://www.iwsec.org/scis/2025/program.html)

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
$ git clone https://github.com/kuwakado/CRPRF.git
$ cd CRPRF
$ make all 
```
When you run "make all", you'll get a lot of warnings, but that's ok.
As a result, two executable files, 'crprf' and 'crprf_moc', are produced in the current directory.

# Usage

To measure the execution time of HMAC of OpenSSL, HMAC, KHC1, and KHC2 for a randomly chosen 256-bit (32-byte) key and message ranging from 0 to 256 bytes in 32-byte increments, type:

```shell-session
$ ./crprf --maxByteLength=256 --repeatCount=129 --stepByte=32
```

In this example, each function was executed 129 times and the execution time was estimated. The execution time shown is the median of the execution time of 129 executions, and the unit is cycles.
For example, the result is displayed to the standard out as follows:

```batch
Bytes , OpenSSL-HMAC , HMAC , KHC1 , KHC2
0 , 4960 , 460 , 200 , 300
32 , 4760 , 480 , 220 , 300
64 , 4840 , 560 , 280 , 300
96 , 4860 , 560 , 280 , 300
128 , 4900 , 640 , 380 , 260
160 , 4860 , 660 , 380 , 380
192 , 5020 , 740 , 460 , 360
224 , 5000 , 740 , 460 , 480
256 , 5040 , 820 , 560 , 440
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
Subtracting the result of 'crprf_moc' from the result of 'crprf' gives the precise execution times of HMAC, KHC1, and KHC2 (i.e., excluding the time for option processing and measurement).
Usage of crcprf_moc is the same as that of crprf.

```shell-session
$ ./crprf_moc --maxByteLength=256 --repeatCount=129 --stepByte=32
```
The result of the above command might look something like this:

```batch
Bytes , OpenSSL-HMAC , HMAC , KHC1 , KHC2
0 , 4740 , 80 , 80 , 80
32 , 4760 , 80 , 80 , 80
64 , 4840 , 80 , 80 , 80
96 , 4800 , 80 , 80 , 80
128 , 4860 , 80 , 80 , 80
160 , 4960 , 80 , 80 , 80
192 , 5020 , 80 , 80 , 80
224 , 4960 , 80 , 80 , 80
256 , 5020 , 80 , 80 , 80
```



# Note

This package does not provide any executable files that allow users to give keys and messages and calculate tags. That is, it does not provide an executable file such as 'sha256sum' command.


# Authors

Hidenori Kuwakado and Shoichi Hirose


# License

[MIT license](https://opensource.org/license/mit)



