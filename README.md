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
cd aes-128; nargo build;
cd aes-256; nargo build;
cd chacha20; nargo build;
```

Use `bytecode` in the *.json file for compiled circuit.

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

## 📊 Performance Benchmarks

### Test Environment

- Data size: 1024 bytes
- Chunk size
  - chacha20: 128 bytes per proof
  - aes-128, aes-256: 80 bytes per proof
- Total proofs generated
  - chacha20: 8 (= 1024/128)
  - aes-128, aes-256: 13 (1024/80 = 12.8, rounded up to 13)
- Algorithm: ChaCha20 symmetric encryption
- Circuit size is measured by `nargo info`.
- Proving time and verification time are measured by running the following script:

```bash
git clone https://github.com/ModoriLabs/zk-symmetric-crypto.git
git checkout bb-benchmark
npm install
cd js && npm run bench
```

### Circuit Metrics

| Algorithm | Circuit Size (gates) | Proving Time(ms) | Verification Time(ms) |
|---|---|---|---|
| **ChaCha20** | 14,190 | 15,108 | 4,520 |
| **AES-128-CTR** | 248,151 | 93,008 | 29,731 |
| **AES-256-CTR** | 355,527 | 121497 | 41224 |

### Hardware Specifications

- **Model:** MacBook Pro (MacBookPro18,1)
- **Chip:** Apple M1 Pro
- **CPU:** 10 cores (8 performance + 2 efficiency)
- **Memory:** 32 GB

## License

[Add license information here]

## Contributing

[Add contributing guidelines here]
