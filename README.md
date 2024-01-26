# FROSTED

## Overview

This repository contains a Flutter application that integrates a Rust-based implementation of the [FROST](https://github.com/ZcashFoundation/frost) (Flexible Round-Optimized Schnorr Threshold) by the Zcash Foundation. It showcases an interactive demo, primarily focused on building cryptocurrency seedless wallets using threshold signatures, enhancing security and flexibility for cryptographic operations.

## Key Features

- `FROST` support: utilizes the FROST library written in Rust, providing robust and secure threshold signature functionality.

- `Ed25519` ciphersuite support.

- `Trusted Dealer Keygen` setup: implements the trusted dealer setup, assuming local communication between participants. This setup is ideal for scenarios where secure, local key distribution is possible, such as in seedless wallets.

- [flutter_rust_bridge](https://github.com/fzyzcjy/flutter_rust_bridge) integration: leverages the `flutter_rust_bridge` for seamless and efficient communication between Dart and Rust, ensuring smooth operation and integration.

### Frosted demo app

Check the [releases page](https://github.com/alienc0der/frosted/releases/latest) for the Windows and MacOS applications.

### Getting Started

#### Prerequisites

- `Flutter SDK`
- `Rust` and `Cargo`
- An understanding of threshold cryptography
- `flutter_rust_bridge` setup

#### Installation

Clone the repository:

```bash
git clone https://github.com/alienc0der/frosted
```

Navigate to the project directory:

```bash
cd frosted
```

Generate the Dart bindings:

```bash
flutter_rust_bridge_codegen generate --watch
```

Run the Flutter application:

```bash
flutter run
```

### Usage

The application demonstrates a seedless wallet scenario:

1. Generate key shards using the Generate Keys button. In a real scenario, the developer must ensure the security of the key shards.
2. Select which key shards will be used for signing.
3. Sign a message and verify the signature. The signature is encoded in `base64`. It is verified using both a Rust and a Dart based implementation.

#### Key shards security ⚠

A secure management of key shards is not implemented. The developer must ensure that all key shards are encrypted and securely stored, and be fully protected against unauthorized access or malicious actors.

### Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

### License

This project is licensed under MIT License - see the LICENSE file for details.

### Acknowledgments

Thanks to the Zcash Foundation for the FROST library.
Gratitude to the `flutter_rust_bridge` team for their excellent tool.
