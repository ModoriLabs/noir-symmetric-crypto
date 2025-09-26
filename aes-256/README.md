# AES-256-CTR Test Suite

This directory contains a comprehensive test suite for the AES-256-CTR implementation in Noir.

## Overview

The test suite validates the AES-256-CTR (Counter mode) implementation against official NIST test vectors and includes additional tests for edge cases and cryptographic properties.

## Test Structure

### Unit Tests (`src/test.nr`)

1. **NIST Vector Tests**
   - `test_aes_256_ctr_nist_vector_1`: Tests the first NIST test vector
   - `test_aes_256_ctr_nist_vector_2`: Tests with incremented counter

2. **Edge Case Tests**
   - `test_aes_256_ctr_zero_plaintext`: Verifies keystream generation with zero plaintext
   - `test_aes_256_ctr_decryption`: Tests the symmetric property of CTR mode

### Integration Test (`src/main.nr`)

The main function serves as an integration test that:
- Takes public inputs (key, counter, plaintext, ciphertext)
- Performs AES-256-CTR encryption
- Verifies the output matches the ciphertext

## Test Vectors

The test vectors are from NIST's AES test suite:

```
Key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
Counter: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Plaintext: 6bc1bee22e409f96e93d7e117393172a
Expected Ciphertext: 601ec313775789a5b7a7f504bbf3d228
```

## Running the Tests

### Prerequisites

- Install Noir: https://noir-lang.org/docs/getting_started/installation
- Ensure `nargo` is in your PATH

### Run All Tests

```bash
./test_runner.sh
```

This script will:
1. Run all unit tests
2. Generate a proof with the NIST test vector
3. Verify the generated proof

### Run Individual Components

```bash
# Run unit tests only
nargo test

# Generate a proof
nargo prove

# Verify a proof
nargo verify

# Check the circuit
nargo check
```

## Test Coverage

The test suite covers:

1. **Correctness**: Validates against known test vectors
2. **Counter Increment**: Tests proper counter handling across blocks
3. **Keystream Properties**: Ensures proper pseudorandom generation
4. **Symmetric Operation**: Verifies encrypt(encrypt(m)) = m property
5. **Bit-level Operations**: Tests the bit manipulation functions

## Adding New Tests

To add new tests:

1. Add test functions to `src/test.nr` with the `#[test]` attribute
2. Use descriptive names following the pattern `test_aes_256_ctr_<description>`
3. Include comments explaining what the test validates
4. Use official test vectors when available

## Troubleshooting

### Common Issues

1. **"nargo: command not found"**
   - Install Noir from the official website
   - Add nargo to your PATH

2. **Compilation Errors**
   - Ensure the `noir-symmetric-crypto` dependency path is correct in `Nargo.toml`
   - Check that all imported modules exist

3. **Test Failures**
   - Verify test vectors are correctly transcribed
   - Check bit ordering (MSB first)
   - Ensure proper array indexing

## References

- [NIST AES Test Vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers)
- [AES Specification (FIPS 197)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [Noir Documentation](https://noir-lang.org/docs)
