# Substitution Ciphers

## Introduction

This Python project implements a substitution cipher known as the Wheatstone cipher, focusing on its encryption and decryption methods.

## Wheatstone Cipher

The Wheatstone cipher is a type of substitution cipher that encrypts plaintext by replacing each letter with another letter based on a key and a square table. The key specifies the starting position of the table, the size of the table, and the corner from which the table is filled.

## Features

- Encryption of plaintext using the Wheatstone cipher.
- Decryption of ciphertext using the Wheatstone cipher.
- Cryptanalysis of Wheatstone ciphertext to determine the key and plaintext.

## Usage

1. Import the `Wheatstone` class from the `wheatstone.py` module.
2. Create an instance of the `Wheatstone` class with the desired key (optional) and pad character (optional).
3. Encrypt plaintext using the `encrypt()` method.
4. Decrypt ciphertext using the `decrypt()` method.
5. Perform cryptanalysis on ciphertext using the `cryptanalyze()` method.

## Example

```python
from wheatstone import Wheatstone

# Create a Wheatstone cipher instance
cipher = Wheatstone()

# Encrypt plaintext
plaintext = "HELLO WORLD"
ciphertext = cipher.encrypt(plaintext)
print("Encrypted:", ciphertext)

# Decrypt ciphertext
decrypted = cipher.decrypt(ciphertext)
print("Decrypted:", decrypted)

# Cryptanalysis
key, plaintext = Wheatstone.cryptanalyze(ciphertext)
print("Key:", key)
print("Plaintext:", plaintext)
