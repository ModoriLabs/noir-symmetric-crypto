# Noir Symmetric Crypto Workspace

A collection of symmetric cryptographic algorithms implemented in Noir, including AES-128, AES-256, and ChaCha20.

## Workspace Structure

This repository is organized as a Noir workspace containing the following packages:

- **noir-symmetric-crypto**: Core library with cryptographic algorithm implementations
- **aes-128**: AES-128 CTR mode binary implementation
- **aes-256**: AES-256 CTR mode binary implementation  
- **chacha20**: ChaCha20 stream cipher binary implementation

## Prerequisites

- [Noir](https://noir-lang.org/docs/getting_started/installation) >= 0.35.0

## Getting Started

Clone the repository:
```bash
git clone https://github.com/ModoriLabs/noir-symmetric-crypto.git
cd noir-symmetric-crypto
```

## Building

Build all packages in the workspace:
```bash
nargo check
```

## Testing

Run all tests across the entire workspace:
```bash
nargo test --workspace
```

This will run tests for all packages:
- Core library tests in `noir-symmetric-crypto`
- AES-128 implementation tests
- AES-256 implementation tests
- ChaCha20 implementation tests

To run tests for a specific package:
```bash
cd aes-256
nargo test
```

## Usage

Each binary package (aes-128, aes-256, chacha20) can be used independently. They all depend on the core `noir-symmetric-crypto` library for the underlying cryptographic implementations.

### Example: AES-256 CTR Mode

```bash
cd aes-256
nargo prove
```

See individual package README files for specific usage instructions.

## License

[Add license information here]

## Contributing

[Add contributing guidelines here]