Moving Window FDH
-----------------

This is an experimental Full Domain Hash (FDH) that is constructed of a moving-window applied against an extendable ouput (XOF) hash function. Unlike a regular Full Domain Hash, it is designed to be contant-time. 

This is experiemental, and has not been formally shown to be secure.

### Background and Rational

A Full Domain Hash is a hash function who's output lies within a specific domain, generally a range `(m, n]`, where `m` is the minimum and `n` is the maximum. 

XOF hash functions can be used directly as a full domain hash when `n` is exactly equal to the highest possible value of an XOF at a give output length. However, this is often not the case. For example, an FDH for use in RSA requires that the length of the FDH be equal to the bit-length of the modulus. However, the *value* of the FDH must lie below the value of the modulus. 

This is traditionally accomplished by constructing an FDH out of a fixed-length hash function and extending it as follows:

```
cycles=(target_length) / (digest_length) + 1
FDH(M) = HASH(M||(SV + 0)) || HASH(M||(SV + 0)) || ... || HASH(M||(SV + cycles−1))

sv = 0
digest = FDH(message)
while not in_domain(digest):
    sv++
    digest = FDH(message, sv)
return digest
```

This traditional method works, but is computationally expensive because it requires recomputing `HASH(M||(IV + 0)` multiple times with every iteration of `IV`. For domains that require many iterations to find an acceptable digest, this can be very computationally expensive. It is also not constant-time in relation to the message being hashed.

### Description

The Moving Window Full Domain Hash (MWFDH) computationally cheap and can be made constant-time, and is constructed as follows:

Pseudocode:
```
H = XOF(message);
digest = H.read_bits(target_length)
while not in_domain(digest):
    digest = digest[1..] || H.read_bits(1) // equivilent to a bitshift
return digest
```

Each iteration of the MWFDH requires only a single bit shift. 

---

<img src="https://raw.githubusercontent.com/phayes/fdh-rs/master/src/movingwindow/docs/figure-1.png" width="50%">

**Figure 1. A Moving Window Full Domain Hash**

In this example, an Extendable Output Hash Function outputs a digest one byte at a time. A moving window is applied against the output to find a one byte Full Domain Hash where the domain is larger than 240 (`11110000`). The final FDH digest value is `11110011`. In a real-world implementation, the digest would be at least 256 bits long.

---

### Constant Time Variant

Because the MWFDH is so computationally cheap, it is practical to use it to constuct a constant-time variation. To construct a constant-time MWFDH, we specificy a fixed number of iterations. As the moving window steps through the underlying XOF Hash Function, it keeps track of how many iterations have been completed, and steps through a fixed-number of iterations regardless of if a valid diget-value was found or not. Regardless of the number of iterations completed, the first valid digest value found is still used as the diget value of the constant-time MWFDH. 

It's possible that the constant-time MWFDH does not find a valid digest value after stepping through the specified fixed-number of iterations. In this case, no digest value is produced and an error is raised. The probability of an error can be strictly bounded by the number of iterations, and can be made a non-issue in practice by specifying a large enough fixed number of iterations. 


---

<img src="https://raw.githubusercontent.com/phayes/fdh-rs/master/src/movingwindow/docs/figure-2.png" width="50%">

**Figure 2. A Constant Time Moving Window Full Domain Hash with 16 iterations**

In this example, an Extendable Output Hash Function outputs a digest one byte at a time. A moving window is applied against the output to find a one byte Full Domain Hash where the domain is larger than 240 (`11110000`). A valid value is found after only 3 iterations, but the the moving window continues to be applied until all 16 iterations are complete. 

---
