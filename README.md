# TSIdentityTool

TSIdentityTool is a small tool that can read out various information about TeamSpeak identities. Moreover, it is also able to generate new identities.

## Build Instructions
1. Make sure you have installed `libtomcrypt` and `libtommath`. If you are running a standard Linux distribution (Ubuntu, Fedora, etc.), you can simply install them from the default repositories. Alternatively, you can compile the libraries from source.
2. Compile with gcc<sup>1</sup>:

   ```
   gcc TSIdentityTool.c -o TSIdentityTool -l tommath -l tomcrypt
   ```
   
<sup>1</sup> TSIdentityTool should compile with LLVM/clang, too. However, the LLVM assembler seems to reject some of the inline assembly from the libtomcrypt/libtommath header files.

   
## Usage
The general usage format is as follows.

​```
./TSIdentityTool COMMAND [OPTIONS]
​```

There are three commands:
* `read inidentity.ini`: Prints basic information about the identity. This could look as follows:
  ```
  Public key: MEwDAgcAAgEgAiEAvX2kANeB4c23aW/bTKK3thz9RudAUWqzqauWpOloLYsCID54CZpzepDZyzxREwf8xNTGyTnaghxQNl+CbS7nb7Kq
  Public key length (Base64): 104
  Fingerprint: Er5KNEMM3ZoatAuGZHmzSj3ZbUw=
  Curve name: ECC-256 (NIST)
  Curve size (octets): 32
  Current security level: 8 (with counter=6)
  ```
* `generate nickname outidentity.ini`: Generates a new identity with name `nickname` and writes it to the file `outidentity.ini`.
* `generategood nickname outidentity.ini`: Generates a new identity with name `nickname` and writes it to the file `outidentity.ini`.
This is similar to the command `generate`, but it additionally makes sure that the Base64 representation of the public key consists of at most 100 characters.
This can come in handy when increasing the security level of the identity.
