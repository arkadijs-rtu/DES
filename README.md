# DES
Implementation of des symmetric cipher in C#

The Data Encryption Standard (DES) is a symmetric-key algorithm for the encryption of digital data. Although its short key length of 56 bits makes it too insecure for modern applications, it has been highly influential in the advancement of cryptography.

Developed in the early 1970s at IBM and based on an earlier design by Horst Feistel, the algorithm was submitted to the National Bureau of Standards (NBS) following the agency's invitation to propose a candidate for the protection of sensitive, unclassified electronic government data. In 1976, after consultation with the National Security Agency (NSA), the NBS selected a slightly modified version (strengthened against differential cryptanalysis, but weakened against brute-force attacks), which was published as an official Federal Information Processing Standard (FIPS) for the United States in 1977

# Usage

Provide 64-bit key, then create new instance of DES class and initalize state

```
  byte[] key = new byte[8] { 0, 0, 0, 0, 0, 0, 0, 0 };

  DES mydes = new DES(keyBytes);
  mydes.Init();
```

Encryption

```
byte[] cipher = mydes.Encrypt(Encoding.ASCII.GetBytes("Hello DES!"));
```

Decryption
```
string result = Encoding.ASCII.GetString(mydes.Decrypt(cipher));
```

# References
https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
