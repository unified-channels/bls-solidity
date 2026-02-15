# BLS12-381 Solidity Library

A Solidity library for BLS12-381 curve operations via EIP-2537 precompiles. Features zero-copy architecture and three abstraction layers for flexible usage.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-^0.8.30-blue)](https://docs.soliditylang.org/)

> **⚠️** This library has NOT been audited. Use at your own risk. Review the security considerations section carefully.


## Overview

This library provides efficient access to BLS12-381 elliptic curve operations on Ethereum through [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537) precompiles. It supports BLS signature verification, polynomial commitments, and other cryptographic primitives requiring pairing-friendly curves with 120+ bits of security.

### Key Features

- **Three Abstraction Layers**: Raw bytes, memory pointers, and typed structs
- **Zero-Copy Architecture**: Returns structs pointing directly to precompile output (no memory copying)
- **Comprehensive Tests**: Test suite with official EIP-2537 test vectors
- **Gas Optimized**: Minimal overhead over raw precompile calls
- **EIP-2537 Compliant**: Compatible with Ethereum precompile specification

## Installation

### Using Foundry (Forge)

```bash
# Install via forge
forge install unified-channels/bls-solidity

# Or install with soldeer
forge soldeer install bls-solidity

# Or add as a submodule
git submodule add https://github.com/unified-channels/bls-solidity.git lib/bls-solidity
```

### Import in Your Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BLS} from "bls-solidity/src/BLS.sol";

contract MyContract {
    function verifySignature(BLS.G1 memory sig, BLS.G2 memory pubkey, bytes32 message) public view returns (bool) {
        // Your verification logic
    }
}
```

## Quick Start

### Example 1: Basic Point Addition

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BLS} from "bls-solidity/src/BLS.sol";

contract Example {
    function addGeneratorToItself() public view returns (BLS.G1 memory) {
        // Get the G1 generator point
        BLS.G1 memory g1 = BLS.g1Generator();

        // Add the point to itself (equivalent to multiplying by 2)
        BLS.G1 memory result = BLS.g1Add(g1, g1);

        return result;
    }
}
```

### Example 2: Scalar Multiplication

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BLS} from "bls-solidity/src/BLS.sol";

contract ScalarMulExample {
    function multiplyByFive() public view returns (BLS.G1 memory) {
        // Create an array with one point
        BLS.G1[] memory points = new BLS.G1[](1);
        points[0] = BLS.g1Generator();

        // Create an array with one scalar
        BLS.Fr[] memory scalars = new BLS.Fr[](1);
        scalars[0] = BLS.Fr.wrap(5); // Multiply by 5

        // Perform multi-scalar multiplication
        return BLS.g1MSM(points, scalars);
    }
}
```

### Example 3: BLS Signature Verification

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BLS} from "bls-solidity/src/BLS.sol";

contract SignatureVerifier {
    /**
     * @notice Verifies a standard BLS signature.
     * @param signature The G1 point representing the signature.
     * @param pubKey The G2 point representing the public key.
     * @param messageHash The G1 point representing the mapped message hash.
     * @return isValid True if the signature is valid.
     */
    function verifySignature(BLS.G1 memory signature, BLS.G2 memory pubKey, BLS.G1 memory messageHash)
        public
        view
        returns (bool isValid)
    {
        BLS.G1[] memory a = new BLS.G1[](2);
        BLS.G2[] memory b = new BLS.G2[](2);

        a[0] = signature;
        b[0] = BLS.negG2Generator();

        a[1] = messageHash;
        b[1] = pubKey;

        return BLS.pairing(a, b);
    }
}
```

### Example 4: Using Raw Precompiles (Low-Level)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BLSPrecompiles} from "bls-solidity/src/BLSPrecompiles.sol";

contract RawPrecompileExample {
    function rawG1Add(bytes memory input) public view returns (bytes memory) {
        // Input must be 256 bytes: two G1 points
        // Each G1 point is 128 bytes: 64 bytes for x, 64 bytes for y
        require(input.length == 256, "Invalid input length");

        // Call the precompile directly
        bytes memory result = BLSPrecompiles.g1Add(input);

        // Result is 128 bytes: one G1 point
        return result;
    }
}
```

## Architecture

The library provides three abstraction layers:

### Layer 1: BLSPrecompiles (Raw Bytes)

Direct bytes-in/bytes-out interface to EIP-2537 precompiles. Lowest overhead.

```solidity
import {BLSPrecompiles} from "bls-solidity/src/BLSPrecompiles.sol";

function rawCall(bytes memory input) public view returns (bytes memory) {
    // Input: 256 bytes (two G1 points)
    // Output: 128 bytes (result G1 point)
    return BLSPrecompiles.g1Add(input);
}
```

**Use when**: You already have bytes-encoded data and want minimal overhead.

### Layer 2: BLSInternal (Memory Pointers)

Memory-pointer based interface with in-place output writing. For advanced users.

```solidity
import {BLSInternal} from "bls-solidity/src/BLSInternal.sol";

function pointerCall(uint256 ptr) public view {
    // ptr points to 256 bytes of input
    // Result written in-place at ptr (first 128 bytes)
    BLSInternal.g1Add(ptr);
    // Read result from ptr
}
```

**Use when**: You need custom memory management or are building higher-level abstractions.

### Layer 3: BLS (Typed Interface) ⭐ Recommended

Type-safe struct-based interface with automatic encoding/decoding. Best developer experience.

```solidity
import {BLS} from "bls-solidity/src/BLS.sol";

function typedCall(BLS.G1 memory a, BLS.G1 memory b) public view returns (BLS.G1 memory) {
    return BLS.g1Add(a, b);
}
```

**Use when**: You want clean, readable code with type safety. **Recommended for most use cases.**

## Gas Benchmarks

Gas costs measured using internal calls with `gasleft()` for accurate overhead calculation.

### Raw Precompile Interface (BLSPrecompiles.sol)

Minimal overhead for direct bytes manipulation:

| Operation | Total Gas | Precompile | Overhead |
|-----------|-----------|------------|----------|
| `g1Add` | 623 | 375 | 248 |
| `g2Add` | 862 | 600 | 262 |
| `g1MSM` (k=1) | 12,249 | 12,000 | 249 |
| `g2MSM` (k=1) | 22,764 | 22,500 | 264 |
| `pairing` (k=1) | 70,539 | 70,300 | 239 |
| `mapFpToG1` | 5,751 | 5,500 | 251 |
| `mapFp2ToG2` | 24,066 | 23,800 | 266 |


### Typed Interface (BLS.sol)

Higher overhead due to struct encoding/decoding:

| Operation | Total Gas | Precompile | Overhead |
|-----------|-----------|------------|----------|
| `g1Add` | 1,766 | 375 | 1,391 |
| `g2Add` | 3,461 | 600 | 2,861 |
| `g1MSM` (k=1) | 13,632 | 12,000 | 1,632 |
| `g2MSM` (k=1) | 25,482 | 22,500 | 2,982 |
| `pairing` (k=1) | 71,246 | 70,300 | 946 |
| `mapToG1` | 6,679 | 5,500 | 1,179 |
| `mapToG2` | 26,284 | 23,800 | 2,484 |

**Overhead breakdown:**
- **G1 operations**: ~1,100-1,400 gas (struct encoding for 128-byte points)
- **G2 operations**: ~2,400-3,000 gas (struct encoding for 256-byte points)
- **Pairing**: ~950 gas (minimal struct work, mainly boolean check)

### Choosing an Interface

**Use BLSPrecompiles when:**
- Gas optimization is critical
- You're working with raw bytes already
- You need maximum performance

**Use BLS when:**
- Code readability matters
- You want type safety
- You're building complex cryptographic protocols
- Gas overhead is acceptable for your use case

### Running Benchmarks

```bash
# Run gas benchmarks with detailed output
forge test -vv

# You'll see output like:
# Gas Reports (BLSPrecompiles.sol):
# Operation: g1Add | Gas: 623 | Precompile Cost: 375 | Overhead: 248
#
# Gas Reports (BLS.sol):
# Operation: g1Add | Gas: 1766 | Precompile Cost: 375 | Overhead: 1391
```

## Data Types

### Fp - Base Field Element

Elements of the base field Fp where p is the BLS12-381 prime modulus.

```solidity
struct Fp {
    uint256 a0; // High bits (top 16 bytes typically zero for valid field elements)
    uint256 a1; // Low 256 bits
}
```

**Total size**: 64 bytes (512 bits)  
**EIP-2537 encoding**: Big-endian, 64 bytes

### Fp2 - Quadratic Extension

Elements of Fp² = Fp[X]/(X² - nr2). Represented as c0 + c1*v where v² = nr2.

```solidity
struct Fp2 {
    Fp c0; // Real part
    Fp c1; // Imaginary part
}
```

**Total size**: 128 bytes  
**EIP-2537 encoding**: encode(c0) || encode(c1)

### G1 - Curve Point (Base Field)

Points on the G1 curve (over Fp) in short Weierstrass form: y² = x³ + 4.

```solidity
struct G1 {
    Fp x;
    Fp y;
}
```

**Total size**: 128 bytes  
**Point at infinity**: All zeros (128 zero bytes)

### G2 - Curve Point (Extension Field)

Points on the G2 curve (over Fp2) in short Weierstrass form.

```solidity
struct G2 {
    Fp2 x;
    Fp2 y;
}
```

**Total size**: 256 bytes  
**Point at infinity**: All zeros (256 zero bytes)

### Fr - Scalar

Scalars for multiplication operations. Can be any uint256 value (not required to be reduced).

```solidity
type Fr is uint256;
```

## API Reference

### BLS Library (Typed Interface)

#### Generator Points

```solidity
// G1 generator point (x, y coordinates per BLS12-381 spec)
function g1Generator() internal pure returns (G1 memory);

// G2 generator point (x, y in Fp2 per BLS12-381 spec)
function g2Generator() internal pure returns (G2 memory);

// Identity element in G1 (point at infinity)
function g1Infinity() internal pure returns (G1 memory);

// Identity element in G2 (point at infinity)
function g2Infinity() internal pure returns (G2 memory);

// Neg G2 Generator point
function negG2Generator() internal pure returns (G2 memory);
```

#### Arithmetic Operations

```solidity
// Add two G1 points: result = a + b
function g1Add(G1 memory a, G1 memory b) internal view returns (G1 memory);

// Add two G2 points: result = a + b
function g2Add(G2 memory a, G2 memory b) internal view returns (G2 memory);

// Multi-scalar multiplication in G1: result = Σ(scalars[i] * points[i])
function g1MSM(G1[] memory points, Fr[] memory scalars) internal view returns (G1 memory);

// Multi-scalar multiplication in G2: result = Σ(scalars[i] * points[i])
function g2MSM(G2[] memory points, Fr[] memory scalars) internal view returns (G2 memory);

// Verify pairing equality: e(a[0], b[0]) * e(a[1], b[1]) * ... == 1
function pairing(G1[] memory a, G2[] memory b) internal view returns (bool);
```

#### Map-to-Curve Operations

```solidity
// Map a field element to a G1 point using SWU algorithm
function mapToG1(Fp memory x) internal view returns (G1 memory);

// Map a field extension element to a G2 point using SWU algorithm
function mapToG2(Fp2 memory x) internal view returns (G2 memory);
```

### BLSPrecompiles Library (Raw Interface)

All functions take `bytes memory` input and return `bytes memory` output.

```solidity
// G1 addition: 256 bytes input (2 points) → 128 bytes output
function g1Add(bytes memory input) internal view returns (bytes memory);

// G2 addition: 512 bytes input (2 points) → 256 bytes output
function g2Add(bytes memory input) internal view returns (bytes memory);

// G1 multi-scalar multiplication: 160*k bytes → 128 bytes output
function g1MSM(bytes memory input) internal view returns (bytes memory);

// G2 multi-scalar multiplication: 288*k bytes → 256 bytes output
function g2MSM(bytes memory input) internal view returns (bytes memory);

// Pairing check: 384*k bytes → 32 bytes output (boolean)
function pairing(bytes memory input) internal view returns (bytes memory);

// Map Fp to G1: 64 bytes → 128 bytes output
function mapFpToG1(bytes memory input) internal view returns (bytes memory);

// Map Fp2 to G2: 128 bytes → 256 bytes output
function mapFp2ToG2(bytes memory input) internal view returns (bytes memory);
```

## Testing

Run the test suite:

```bash
# Run all tests
forge test

# Run with gas benchmarks
forge test -vv

# Run specific test file
forge test --match-path test/BLS.t.sol

# Run with high verbosity
forge test -vvv
```

### Test Coverage

- **Unit Tests**: All precompile operations with valid inputs
- **Invalid Input Tests**: Precompile error handling
- **Integration Tests**: End-to-end workflows
- **EIP-2537 Test Vectors**: Official test vectors from Ethereum specification
- **Gas Benchmarks**: Internal overhead measurement

## Security Considerations

⚠️ **Important Security Notes:**

1. **NOT AUDITED**: This library has not been audited. Use at your own risk.

2. **Input Validation**: EIP-2537 precompiles validate all inputs:
   - Points must be on the curve
   - Field elements must be < modulus
   - MSM and pairing operations check subgroup membership

3. **Gas Burning**: Failed precompile calls burn ALL supplied gas (EIP-2537 requirement)

4. **No Constant Time Guarantees**: Precompiles are not required to be constant-time

5. **Point at Infinity**: 
   - G1: 128 zero bytes
   - G2: 256 zero bytes
   - Note: (0,0) is not on the curve, used by convention

6. **Subgroup Checks**:
   - G1ADD and G2ADD: NO subgroup checks
   - G1MSM and G2MSM: Mandatory subgroup checks
   - Pairing: All points must be in correct subgroup

7. **MEV Considerations**: Cryptographic operations may be vulnerable to front-running in certain contexts


## EIP-2537 Compliance

All EIP-2537 precompiles are implemented:

| Precompile | Address | Operation | Base Gas |
|------------|---------|-----------|----------|
| BLS12_G1ADD | 0x0b | G1 addition | 375 |
| BLS12_G1MSM | 0x0c | G1 multi-scalar multiplication | Variable* |
| BLS12_G2ADD | 0x0d | G2 addition | 600 |
| BLS12_G2MSM | 0x0e | G2 multi-scalar multiplication | Variable* |
| BLS12_PAIRING_CHECK | 0x0f | Pairing equality check | Variable** |
| BLS12_MAP_FP_TO_G1 | 0x10 | Fp → G1 mapping | 5,500 |
| BLS12_MAP_FP2_TO_G2 | 0x11 | Fp2 → G2 mapping | 23,800 |

**MSM gas**: (k × multiplication_cost × discount) / 1000  
**Pairing gas**: 32600 × k + 37700

## Development

### Setup

```bash
# Clone repository
git clone https://github.com/unified-channels/bls-solidity.git
cd bls-solidity

# Install dependencies
forge install

# Run tests
forge test

# Run gas benchmarks
forge test -vv

# Format code
forge fmt

# Build
forge build
```

### Project Structure

```
├── src/
│   ├── BLS.sol              # Typed interface (recommended)
│   ├── BLSInternal.sol      # Memory pointer interface
│   └── BLSPrecompiles.sol   # Raw bytes interface
├── test/
│   ├── BLS.t.sol           # Integration tests
│   ├── BLSGas.t.sol        # Gas benchmarks
│   ├── Signature.t.sol     # Signature verification tests
│   └── precompiles/        # Individual precompile tests
├── test/vectors/           # EIP-2537 test vectors
└── README.md
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537) authors: Alex Vlasov, Kelly Olson, Alex Stokes, Antonio Sanso
- Ethereum Foundation for BLS12-381 precompile specification
- [Foundry](https://github.com/foundry-rs/foundry) for the development framework

## Resources

- [EIP-2537 Specification](https://eips.ethereum.org/EIPS/eip-2537)
- [BLS Signatures Standard](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05)
- [Ethereum BLS12-381 Test Vectors](https://github.com/ethereum/bls12-381-tests)

---

**Requirements**: This library requires an EIP-2537-enabled environment (Ethereum mainnet post-Pectra upgrade or compatible testnets).
