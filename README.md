# Auth1

Minimal login/signup authentication example using secure password hashing.

## What is implemented

- Signup stores passwords as PBKDF2-SHA256 hashes with random salt.
- Login verifies passwords against stored hashes.
- Constant-time digest comparison is used to reduce timing attacks.

## Run tests

```bash
python -m unittest discover -s tests
```