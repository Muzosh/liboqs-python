# liboqs-python

This repository documents the process of building the Python extension of liboqs library.

## Prerequisites
Pip, Python Hatch, cmake, ninja, and a C compiler (e.g. gcc) are required to build the extension.

## Installation

1. Clone this repository
2. If you already have libOQS repository on the system, specify its location by `export LIBOQS_ROOT=/path/to/liboqs`
3. Run `build.sh` to build dependencies and python package
4. Run `pip install --upgrade --force-reinstall dist/oqspython-*.whl` to install the package into your pip environment
5. `from oqs import oqspython` in your Python code (based on where it is located relative to the Python file)

## Exposed classes and functions

Should be visible in IDE when `oqspython` is imported. Otherwise, see `oqspython.i` or `oqspython.py`.

## Example

```python
from oqs import oqspython

sig = oqspython.OQS_SIGNATURE(oqspython.OQS_SIG_alg_dilithium_5)

public_key = bytes(sig.length_public_key)
private_key = bytes(sig.length_private_key)

message = b"This is the message to sign"

result = sig.keypair(public_key, private_key)
assert result == oqspython.OQS_SUCCESS

signature = bytes(sig.length_signature)
result = sig.sign(signature, message, len(message), private_key)
assert result == oqspython.OQS_SUCCESS

result = sig.verify(message, len(message), signature, public_key)
assert result == oqspython.OQS_SUCCESS

kem = oqspython.OQS_KEYENCAPSULATION(oqspython.OQS_KEM_alg_kyber_1024)

public_key = bytes(kem.length_public_key)
private_key = bytes(kem.length_private_key)

result = kem.keypair(public_key, private_key)
assert result == oqspython.OQS_SUCCESS

shared_secret = bytes(kem.length_shared_secret)
ciphertext = bytes(kem.length_ciphertext)
result = kem.encapsulate(ciphertext, shared_secret, public_key)
assert result == oqspython.OQS_SUCCESS

shared_secret2 = bytes(kem.length_shared_secret)
result = kem.decapsulate(shared_secret2, ciphertext, private_key)
assert result == oqspython.OQS_SUCCESS

assert shared_secret == shared_secret2

print("Finished successfully")
```
