# liboqs-python

This repository documents the process of building the PHP extension of liboqs library.

## Prerequisites

You will need to build liboqs itself. Basically follow the steps in <https://github.com/open-quantum-safe/liboqs#quickstart> (no need to build with some modified -D arguments). Preliminary is to have `liboqs.a` in `build/lib` and header files in `build/include`.

## Installation

1. Clone this repository
1. Define liboqs root directory in `compile.sh` (LIBOQS_ROOT_DIR)
1. Change `CP_PATH` commands in `compile.sh` so that `oqspython.py` and `_oqspython.so` are copied into your Python project
1. Run `compile.sh`
1. Ensure that `oqspython.py`, `_oqspython.so`, and `__init__.py` are in the same directory
1. Import `oqspython` in your Python code (based on where it is located relative to the Python file)

## Exposed classes and functions

Should be visible in IDE when `oqspython` is imported. Otherwise, see `oqspython.i`.

## Example

```python
from oqspython import oqspython

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
