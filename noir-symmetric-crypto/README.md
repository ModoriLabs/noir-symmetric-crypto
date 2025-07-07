# noir-symmetric-crypto

Zero-knowledge proof circuits for symmetric cryptographic operations in Noir. This library enables you to prove knowledge of encryption keys and plaintexts without revealing them.

## Overview

This library provides Noir implementations of common symmetric encryption algorithms. It allows you to prove statements about encrypted data while keeping the keys and plaintexts private.

Supported algorithms:

- AES-128/192/256 in CTR mode
- ChaCha20 stream cipher

## Usage

## Security Considerations

1. This library provides the cryptographic operations but does not enforce secure usage. You must ensure:

   - Proper key generation and management
   - No key reuse
   - Secure counter/nonce handling

2. The circuits prove knowledge of inputs that satisfy the encryption/decryption relationship. They do not prove anything about the security of the keys or plaintexts themselves.

## Contributing

Contributions are welcome! Please feel free to submit pull requests. Areas for improvement:

- Additional cipher implementations
- Performance optimizations
- Better test coverage
- Documentation improvements

## Testing

## Benchmarks

Constraint counts for different operations:

- AES-128-CTR: ~X constraints
- AES-256-CTR: ~Y constraints
- ChaCha20: ~Z constraints

## Acknowledgments

This library is a Noir port of [zk-symmetric-crypto](link) which provided the original circom implementations.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contact

- GitHub Issues: [noir-symmetric-crypto/issues](https://github.com/tx-tomcat/noir-symmetric-crypto/issues)
- Twitter: [@dzungdinhnguyen](https://x.com/dzungdinhnguyen)
