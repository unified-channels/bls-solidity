// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

/**
 * @title BLSInternal
 * @notice Zero-copy internal wrapper for EIP-2537 BLS12-381 precompiles
 * @dev This library provides a thin abstraction over precompile calls with:
 * - Memory-pointer based interface (avoids bytes allocation overhead)
 * - In-place output writing (reuses input buffer to save memory)
 * - Minimal gas overhead
 *
 * Architecture Pattern:
 * - Callers allocate scratch space and write input data
 * - Precompile overwrites input with output (same or smaller size)
 * - Callers read results directly from the memory pointer
 *
 * Memory Safety:
 * - All functions assume properly allocated memory at `ptr`
 * - Output size is validated against EIP-2537 specification
 * - Reverts on precompile failure with no error data (EIP-2537 behavior)
 *
 * For high-level typed interface, see BLS.sol
 */
library BLSInternal {
    /// @notice EIP-2537 precompile address for G1 point addition (BLS12_G1ADD at 0x0b)
    /// @dev Gas: 375 | Input: 256 bytes at ptr | Output: 128 bytes at ptr
    uint256 internal constant G1_ADD = 0x0b;

    /// @notice EIP-2537 precompile address for G1 multi-scalar multiplication (BLS12_G1MSM at 0x0c)
    /// @dev Gas: Variable | Input: 160*k bytes at ptr | Output: 128 bytes at ptr
    /// @dev Performs subgroup checks on all points
    uint256 internal constant G1_MSM = 0x0c;

    /// @notice EIP-2537 precompile address for G2 point addition (BLS12_G2ADD at 0x0d)
    /// @dev Gas: 600 | Input: 512 bytes at ptr | Output: 256 bytes at ptr
    uint256 internal constant G2_ADD = 0x0d;

    /// @notice EIP-2537 precompile address for G2 multi-scalar multiplication (BLS12_G2MSM at 0x0e)
    /// @dev Gas: Variable | Input: 288*k bytes at ptr | Output: 256 bytes at ptr
    /// @dev Performs subgroup checks on all points
    uint256 internal constant G2_MSM = 0x0e;

    /// @notice EIP-2537 precompile address for pairing check (BLS12_PAIRING_CHECK at 0x0f)
    /// @dev Gas: 32600*k + 37700 | Input: 384*k bytes at ptr | Output: 32 bytes at ptr
    uint256 internal constant PAIRING = 0x0f;

    /// @notice EIP-2537 precompile address for Fp to G1 mapping (BLS12_MAP_FP_TO_G1 at 0x10)
    /// @dev Gas: 5500 | Input: 64 bytes at ptr | Output: 128 bytes at ptr (overwrites)
    uint256 internal constant MAP_FP_G1 = 0x10;

    /// @notice EIP-2537 precompile address for Fp2 to G2 mapping (BLS12_MAP_FP2_TO_G2 at 0x11)
    /// @dev Gas: 23800 | Input: 128 bytes at ptr | Output: 256 bytes at ptr (overwrites)
    uint256 internal constant MAP_FP2_G2 = 0x11;

    /**
     * @notice Adds two G1 points using BLS12_G1ADD precompile
     * @dev Writes result in-place at the input pointer location
     *
     * Memory Layout at `ptr`:
     * - Input (256 bytes):
     *   - [ptr, ptr+128): First G1 point (x, y as Fp elements)
     *   - [ptr+128, ptr+256): Second G1 point (x, y as Fp elements)
     * - Output (128 bytes, overwrites first 128 bytes of input):
     *   - [ptr, ptr+128): Result G1 point
     *
     * Coordinate Encoding:
     * - Each Fp element: 64 bytes (big-endian, top 16 bytes zero)
     * - Each G1 point: 128 bytes (x: 64 bytes, y: 64 bytes)
     * - Point at infinity: All 128 bytes zero
     *
     * @param ptr Memory pointer to 256-byte input buffer (will be overwritten with 128-byte output)
     *
     * @custom:reverts If precompile call fails (invalid input, points not on curve)
     * @custom:reverts If returndatasize != 128 bytes
     * @custom:note No subgroup check performed
     * @custom:warning Input buffer must have at least 256 bytes allocated; first 128 bytes will be overwritten
     */
    function g1Add(uint256 ptr) internal view {
        assembly {
            // Execute static call to BLS12_G1ADD precompile
            // - gas(): Forward all remaining gas
            // - G1_ADD (0x0b): Precompile address
            // - ptr: Input starts here (256 bytes)
            // - 256: Input size (two G1 points)
            // - ptr: Write output here (128 bytes, overwrites first G1 point)
            // - 128: Expected output size
            let success := staticcall(gas(), G1_ADD, ptr, 256, ptr, 128)

            // EIP-2537: Revert on failure, burning all gas
            if iszero(success) { revert(0, 0) }

            // Validate output size per EIP-2537 specification
            if iszero(eq(returndatasize(), 128)) { revert(0, 0) }
        }
    }

    /**
     * @notice Adds two G2 points using BLS12_G2ADD precompile
     * @dev Writes result in-place at the input pointer location
     *
     * Memory Layout at `ptr`:
     * - Input (512 bytes):
     *   - [ptr, ptr+256): First G2 point (x, y as Fp2 elements)
     *   - [ptr+256, ptr+512): Second G2 point (x, y as Fp2 elements)
     * - Output (256 bytes, overwrites first 256 bytes of input):
     *   - [ptr, ptr+256): Result G2 point
     *
     * Coordinate Encoding:
     * - Each Fp2 element: 128 bytes (c0: 64 bytes, c1: 64 bytes)
     * - Each G2 point: 256 bytes (x: 128 bytes, y: 128 bytes)
     * - Point at infinity: All 256 bytes zero
     *
     * @param ptr Memory pointer to 512-byte input buffer (will be overwritten with 256-byte output)
     *
     * @custom:reverts If precompile call fails
     * @custom:reverts If returndatasize != 256 bytes
     * @custom:note No subgroup check performed
     * @custom:warning Input buffer must have at least 512 bytes allocated; first 256 bytes will be overwritten
     */
    function g2Add(uint256 ptr) internal view {
        assembly {
            // Call BLS12_G2ADD (0x0d)
            // Input: 512 bytes (two G2 points)
            // Output: 256 bytes (one G2 point)
            if iszero(staticcall(gas(), G2_ADD, ptr, 512, ptr, 256)) { revert(0, 0) }

            // Validate return size
            if iszero(eq(returndatasize(), 256)) { revert(0, 0) }
        }
    }

    /**
     * @notice Computes multi-scalar multiplication in G1 using BLS12_G1MSM precompile
     * @dev Uses Pippenger's algorithm for efficiency
     *
     * Memory Layout at `ptr`:
     * - Input (160 * length bytes):
     *   - For each i in [0, length):
     *     - [ptr + i*160, ptr + i*160 + 128): G1 point
     *     - [ptr + i*160 + 128, ptr + i*160 + 160): Scalar (32 bytes, big-endian)
     * - Output (128 bytes, overwrites first part of input):
     *   - [ptr, ptr+128): Result G1 point
     *
     * Mathematical Operation:
     * - Computes: s_0 * P_0 + s_1 * P_1 + ... + s_{k-1} * P_{k-1}
     * - Where s_i are scalars and P_i are G1 points
     *
     * Gas Calculation:
     * - Formula: (k * 12000 * discount(k)) / 1000
     * - discount(k) from EIP-2537 table (min 519 for k > 128)
     *
     * @param ptr Memory pointer to input buffer containing (point, scalar) pairs
     * @param length Number of (point, scalar) pairs (k), must be >= 1
     *
     * @custom:reverts If length == 0
     * @custom:reverts If any point not on curve or not in subgroup
     * @custom:reverts If returndatasize != 128 bytes
     * @custom:note Performs mandatory subgroup checks
     * @custom:warning First 128 bytes of input buffer will be overwritten
     */
    function g1MSM(uint256 ptr, uint256 length) internal view {
        assembly {
            // Calculate total input size: 160 bytes per pair
            // - 128 bytes for G1 point
            // - 32 bytes for scalar
            let inputSize := mul(length, 160)

            // Call BLS12_G1MSM (0x0c)
            // - ptr: Input buffer start
            // - inputSize: Total input length
            // - ptr: Output written here (128 bytes)
            // - 128: Expected output size
            if iszero(staticcall(gas(), G1_MSM, ptr, inputSize, ptr, 128)) { revert(0, 0) }

            // Validate output size
            if iszero(eq(returndatasize(), 128)) { revert(0, 0) }
        }
    }

    /**
     * @notice Computes multi-scalar multiplication in G2 using BLS12_G2MSM precompile
     * @dev Uses Pippenger's algorithm for efficiency on curve over Fp2
     *
     * Memory Layout at `ptr`:
     * - Input (288 * length bytes):
     *   - For each i in [0, length):
     *     - [ptr + i*288, ptr + i*288 + 256): G2 point
     *     - [ptr + i*288 + 256, ptr + i*288 + 288): Scalar (32 bytes)
     * - Output (256 bytes, overwrites first part of input):
     *   - [ptr, ptr+256): Result G2 point
     *
     * Mathematical Operation:
     * - Computes: s_0 * P_0 + s_1 * P_1 + ... + s_{k-1} * P_{k-1}
     * - Where s_i are scalars and P_i are G2 points
     *
     * Gas Calculation:
     * - Formula: (k * 22500 * discount(k)) / 1000
     * - discount(k) from EIP-2537 table (min 524 for k > 128)
     *
     * @param ptr Memory pointer to input buffer containing (point, scalar) pairs
     * @param length Number of (point, scalar) pairs (k), must be >= 1
     *
     * @custom:reverts If length == 0
     * @custom:reverts If any point not on curve or not in subgroup
     * @custom:reverts If returndatasize != 256 bytes
     * @custom:note Performs mandatory subgroup checks
     * @custom:warning First 256 bytes of input buffer will be overwritten
     */
    function g2MSM(uint256 ptr, uint256 length) internal view {
        assembly {
            // Calculate total input size: 288 bytes per pair
            // - 256 bytes for G2 point
            // - 32 bytes for scalar
            let inputSize := mul(length, 288)

            // Call BLS12_G2MSM (0x0e)
            // Output: 256 bytes at same location
            if iszero(staticcall(gas(), G2_MSM, ptr, inputSize, ptr, 256)) { revert(0, 0) }

            // Validate return size
            if iszero(eq(returndatasize(), 256)) { revert(0, 0) }
        }
    }

    /**
     * @notice Verifies pairing equality using BLS12_PAIRING_CHECK precompile
     * @dev Checks if product of pairings equals identity in target group
     *
     * Memory Layout at `ptr`:
     * - Input (384 * length bytes):
     *   - For each i in [0, length):
     *     - [ptr + i*384, ptr + i*384 + 128): G1 point
     *     - [ptr + i*384 + 128, ptr + i*384 + 384): G2 point
     * - Output (32 bytes, overwrites first part of input):
     *   - [ptr, ptr+32): Boolean result
     *   - Format: 31 zero bytes + 0x01 (true) or 0x00 (false)
     *
     * Mathematical Check:
     * - Verifies: e(P_0, Q_0) * e(P_1, Q_1) * ... * e(P_{k-1}, Q_{k-1}) == 1
     * - Where e is the optimal ate pairing
     *
     * Gas Cost:
     * - Formula: 32600 * k + 37700
     *
     * @param ptr Memory pointer to input buffer containing (G1, G2) point pairs
     * @param length Number of point pairs (k), must be >= 1
     *
     * @custom:reverts If length == 0
     * @custom:reverts If any point not on curve or not in subgroup
     * @custom:reverts If returndatasize != 32 bytes
     * @custom:note All points must be in correct subgroup
     * @custom:warning First 32 bytes of input buffer will be overwritten
     */
    function pairing(uint256 ptr, uint256 length) internal view {
        assembly {
            // Calculate total input size: 384 bytes per pair
            // - 128 bytes for G1 point
            // - 256 bytes for G2 point
            let inputSize := mul(length, 384)

            // Call BLS12_PAIRING_CHECK (0x0f)
            // Output: 32 bytes (boolean encoded as per EIP-2537)
            if iszero(staticcall(gas(), PAIRING, ptr, inputSize, ptr, 32)) { revert(0, 0) }

            // Validate return size
            if iszero(eq(returndatasize(), 32)) { revert(0, 0) }
        }
    }

    /**
     * @notice Maps Fp element to G1 point using BLS12_MAP_FP_TO_G1 precompile
     * @dev Uses SWU (Simplified Shallue-van de Woestijne-Ulas) algorithm
     *
     * Memory Layout at `ptr`:
     * - Input (64 bytes):
     *   - [ptr, ptr+64): Fp element (a0: 32 bytes, a1: 32 bytes)
     * - Output (128 bytes, overwrites input):
     *   - [ptr, ptr+128): G1 point (x, y coordinates)
     *
     * Algorithm Properties:
     * - Deterministic: same input always maps to same output
     * - Uniform: output distribution is uniform across G1
     * - Output is always in correct subgroup
     *
     * @param ptr Memory pointer to 64-byte Fp element (will be overwritten with 128-byte G1 point)
     *
     * @custom:reverts If Fp element >= field modulus
     * @custom:reverts If returndatasize != 128 bytes
     * @custom:note Output point is guaranteed to be in subgroup
     * @custom:warning First 64 bytes of input will be overwritten (reads 64, writes 128)
     */
    function mapFpToG1(uint256 ptr) internal view {
        assembly {
            // Call BLS12_MAP_FP_TO_G1 (0x10)
            // Input: 64 bytes (Fp element)
            // Output: 128 bytes (G1 point), written at same location
            if iszero(staticcall(gas(), MAP_FP_G1, ptr, 64, ptr, 128)) { revert(0, 0) }

            // Validate return size
            if iszero(eq(returndatasize(), 128)) { revert(0, 0) }
        }
    }

    /**
     * @notice Maps Fp2 element to G2 point using BLS12_MAP_FP2_TO_G2 precompile
     * @dev Uses SWU algorithm on field extension Fp2
     *
     * Memory Layout at `ptr`:
     * - Input (128 bytes):
     *   - [ptr, ptr+64): c0 (real part as Fp)
     *   - [ptr+64, ptr+128): c1 (imaginary part as Fp)
     * - Output (256 bytes, overwrites input):
     *   - [ptr, ptr+256): G2 point (x, y as Fp2 elements)
     *
     * Algorithm Properties:
     * - Deterministic and uniform mapping on Fp2
     * - Output is always in correct subgroup
     *
     * Gas Cost: 23800
     *
     * @param ptr Memory pointer to 128-byte Fp2 element (will be overwritten with 256-byte G2 point)
     *
     * @custom:reverts If Fp2 components >= field modulus
     * @custom:reverts If returndatasize != 256 bytes
     * @custom:note Output point is guaranteed to be in subgroup
     * @custom:warning First 128 bytes of input will be overwritten (reads 128, writes 256)
     */
    function mapFp2ToG2(uint256 ptr) internal view {
        assembly {
            // Call BLS12_MAP_FP2_TO_G2 (0x11)
            // Input: 128 bytes (Fp2 element)
            // Output: 256 bytes (G2 point), written at same location
            if iszero(staticcall(gas(), MAP_FP2_G2, ptr, 128, ptr, 256)) { revert(0, 0) }

            // Validate return size
            if iszero(eq(returndatasize(), 256)) { revert(0, 0) }
        }
    }
}
