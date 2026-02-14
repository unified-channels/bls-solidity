// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

/**
 * @title BLSPrecompiles
 * @notice Low-level wrapper library for EIP-2537 BLS12-381 precompiles
 * @dev Provides raw byte-level access to all BLS12-381 curve operations.
 * This is the lowest abstraction layer - callers must handle:
 * - Input encoding according to EIP-2537 specification
 * - Memory allocation for outputs
 * - Error handling from invalid inputs
 *
 * All functions use the bytes memory type for maximum flexibility.
 * For typed wrappers with automatic encoding, see BLS.sol
 */
library BLSPrecompiles {
    /// @notice EIP-2537 precompile address for G1 point addition (BLS12_G1ADD)
    /// @dev Gas cost: 375 | Input: 256 bytes (2 G1 points) | Output: 128 bytes
    uint256 internal constant G1_ADD = 0x0b;

    /// @notice EIP-2537 precompile address for G1 multi-scalar multiplication (BLS12_G1MSM)
    /// @dev Gas cost: Variable (see EIP-2537 discount table) | Input: 160*k bytes | Output: 128 bytes
    /// @dev Performs subgroup checks on all input points
    uint256 internal constant G1_MSM = 0x0c;

    /// @notice EIP-2537 precompile address for G2 point addition (BLS12_G2ADD)
    /// @dev Gas cost: 600 | Input: 512 bytes (2 G2 points) | Output: 256 bytes
    uint256 internal constant G2_ADD = 0x0d;

    /// @notice EIP-2537 precompile address for G2 multi-scalar multiplication (BLS12_G2MSM)
    /// @dev Gas cost: Variable (see EIP-2537 discount table) | Input: 288*k bytes | Output: 256 bytes
    /// @dev Performs subgroup checks on all input points
    uint256 internal constant G2_MSM = 0x0e;

    /// @notice EIP-2537 precompile address for pairing equality check (BLS12_PAIRING_CHECK)
    /// @dev Gas cost: 32600*k + 37700 | Input: 384*k bytes | Output: 32 bytes
    /// @dev Verifies: e(P1,Q1) * e(P2,Q2) * ... * e(Pk,Qk) == 1
    uint256 internal constant PAIRING = 0x0f;

    /// @notice EIP-2537 precompile address for mapping Fp element to G1 point (BLS12_MAP_FP_TO_G1)
    /// @dev Gas cost: 5500 | Input: 64 bytes (Fp element) | Output: 128 bytes (G1 point)
    /// @dev Uses SWU (Simplified Shallue-van de Woestijne-Ulas) map-to-curve algorithm
    uint256 internal constant MAP_FP_G1 = 0x10;

    /// @notice EIP-2537 precompile address for mapping Fp2 element to G2 point (BLS12_MAP_FP2_TO_G2)
    /// @dev Gas cost: 23800 | Input: 128 bytes (Fp2 element) | Output: 256 bytes (G2 point)
    /// @dev Uses SWU map-to-curve algorithm on field extension
    uint256 internal constant MAP_FP2_G2 = 0x11;

    /**
     * @notice Performs point addition in G1 (curve over base field Fp)
     * @dev Calls BLS12_G1ADD precompile at address 0x0b
     *
     * Memory Layout:
     * - Input: 256 bytes contiguous
     *   - Bytes 0-127: First G1 point (x, y coordinates, 64 bytes each)
     *   - Bytes 128-255: Second G1 point (x, y coordinates, 64 bytes each)
     * - Output: 128 bytes
     *   - Bytes 0-63: Result x coordinate
     *   - Bytes 64-127: Result y coordinate
     *
     * Point at Infinity Encoding:
     * - Both coordinates zero (128 zero bytes) represents the identity element
     *
     * @param input 256 bytes encoded as per EIP-2537 (two G1 points)
     * @return output 128 bytes encoding the resulting G1 point
     *
     * @custom:reverts If precompile execution fails (invalid input encoding, point not on curve)
     * @custom:reverts If return data size != 128 bytes
     * @custom:note No subgroup check performed by this precompile
     */
    function g1Add(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            // Allocate output buffer: 32 bytes (length prefix) + 128 bytes (data)
            output := mload(0x40)
            mstore(0x40, add(output, 0xa0))
            mstore(output, 128)

            // Execute static call to precompile
            // staticcall(gas, address, argsOffset, argsSize, retOffset, retSize)
            // - argsOffset: add(input, 0x20) - skip bytes length prefix
            // - argsSize: mload(input) - actual data length from prefix
            // - retOffset: add(output, 0x20) - skip our length prefix
            // - retSize: 128 bytes (G1 point size)
            if iszero(staticcall(gas(), G1_ADD, add(input, 0x20), mload(input), add(output, 0x20), 128)) {
                revert(0, 0)
            }

            // EIP-2537 requires return size validation
            if iszero(eq(returndatasize(), 128)) { revert(0, 0) }
        }
    }

    /**
     * @notice Performs point addition in G2 (curve over field extension Fp2)
     * @dev Calls BLS12_G2ADD precompile at address 0x0d
     *
     * Memory Layout:
     * - Input: 512 bytes contiguous
     *   - Bytes 0-255: First G2 point (x, y in Fp2, 128 bytes each)
     *   - Bytes 256-511: Second G2 point (x, y in Fp2, 128 bytes each)
     * - Output: 256 bytes
     *   - Bytes 0-127: Result x coordinate (Fp2 element)
     *   - Bytes 128-255: Result y coordinate (Fp2 element)
     *
     * @param input 512 bytes encoded as per EIP-2537 (two G2 points)
     * @return output 256 bytes encoding the resulting G2 point
     *
     * @custom:reverts If precompile execution fails
     * @custom:reverts If return data size != 256 bytes
     * @custom:note No subgroup check performed by this precompile
     */
    function g2Add(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            // Allocate output buffer: 32 bytes (length) + 256 bytes (data)
            output := mload(0x40)
            mstore(0x40, add(output, 0x120))
            mstore(output, 256)

            // Execute static call
            if iszero(staticcall(gas(), G2_ADD, add(input, 0x20), mload(input), add(output, 0x20), 256)) {
                revert(0, 0)
            }

            // Validate return data size
            if iszero(eq(returndatasize(), 256)) { revert(0, 0) }
        }
    }

    /**
     * @notice Performs multi-scalar multiplication in G1 using Pippenger's algorithm
     * @dev Calls BLS12_G1MSM precompile at address 0x0c
     *
     * Memory Layout:
     * - Input: 160 * k bytes where k >= 1
     *   - For each pair i in [0, k-1]:
     *     - Bytes i*160 + 0-127: G1 point
     *     - Bytes i*160 + 128-159: Scalar (32 bytes, big-endian)
     * - Output: 128 bytes (single G1 point)
     *
     * Gas Calculation (EIP-2537):
     * - Base: k * 12000 * discount(k) / 1000
     * - discount(k) from lookup table (519 min for k > 128)
     *
     * @param input 160*k bytes encoding k (point, scalar) pairs
     * @return output 128 bytes encoding the MSM result
     *
     * @custom:reverts If input empty (k = 0)
     * @custom:reverts If input length not divisible by 160
     * @custom:reverts If any point not on curve or not in subgroup
     * @custom:reverts If return data size != 128 bytes
     * @custom:note Performs mandatory subgroup checks per EIP-2537
     */
    function g1MSM(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            // Allocate output buffer
            output := mload(0x40)
            mstore(0x40, add(output, 0xa0))
            mstore(output, 128)

            // Execute MSM precompile
            if iszero(staticcall(gas(), G1_MSM, add(input, 0x20), mload(input), add(output, 0x20), 128)) {
                revert(0, 0)
            }

            // Validate return
            if iszero(eq(returndatasize(), 128)) { revert(0, 0) }
        }
    }

    /**
     * @notice Performs multi-scalar multiplication in G2 using Pippenger's algorithm
     * @dev Calls BLS12_G2MSM precompile at address 0x0e
     *
     * Memory Layout:
     * - Input: 288 * k bytes where k >= 1
     *   - For each pair i in [0, k-1]:
     *     - Bytes i*288 + 0-255: G2 point
     *     - Bytes i*288 + 256-287: Scalar (32 bytes, big-endian)
     * - Output: 256 bytes (single G2 point)
     *
     * Gas Calculation (EIP-2537):
     * - Base: k * 22500 * discount(k) / 1000
     * - discount(k) from lookup table (524 min for k > 128)
     *
     * @param input 288*k bytes encoding k (point, scalar) pairs
     * @return output 256 bytes encoding the MSM result
     *
     * @custom:reverts If input empty or wrong size
     * @custom:reverts If any point not on curve or not in subgroup
     * @custom:reverts If return data size != 256 bytes
     * @custom:note Performs mandatory subgroup checks per EIP-2537
     */
    function g2MSM(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            // Allocate output buffer
            output := mload(0x40)
            mstore(0x40, add(output, 0x120))
            mstore(output, 256)

            // Execute MSM precompile
            if iszero(staticcall(gas(), G2_MSM, add(input, 0x20), mload(input), add(output, 0x20), 256)) {
                revert(0, 0)
            }

            // Validate return size
            if iszero(eq(returndatasize(), 256)) { revert(0, 0) }
        }
    }

    /**
     * @notice Verifies pairing equality: e(P1,Q1) * e(P2,Q2) * ... * e(Pk,Qk) == 1
     * @dev Calls BLS12_PAIRING_CHECK precompile at address 0x0f
     *
     * Memory Layout:
     * - Input: 384 * k bytes where k >= 1
     *   - For each pair i in [0, k-1]:
     *     - Bytes i*384 + 0-127: G1 point
     *     - Bytes i*384 + 128-383: G2 point
     * - Output: 32 bytes
     *   - Bytes 0-30: Always zero
     *   - Byte 31: 0x01 if pairing holds, 0x00 otherwise
     *
     * Mathematical Property:
     * - Bilinearity: e(a*P, b*Q) = e(P, Q)^(a*b)
     * - Non-degeneracy: e(G1, G2) != 1 for generators
     * - Identity: e(P, O) = e(O, Q) = 1
     *
     * Gas Cost: 32600 * k + 37700
     *
     * @param input 384*k bytes encoding k (G1, G2) point pairs
     * @return output 32 bytes with boolean result in last byte
     *
     * @custom:reverts If input empty or wrong size
     * @custom:reverts If any point not on curve or not in subgroup
     * @custom:reverts If return data size != 32 bytes
     * @custom:note All input points must be in correct subgroup
     */
    function pairing(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            // Allocate output buffer (only need 32 bytes for boolean)
            output := mload(0x40)
            mstore(0x40, add(output, 0x40))
            mstore(output, 32)

            // Execute pairing check
            if iszero(staticcall(gas(), PAIRING, add(input, 0x20), mload(input), add(output, 0x20), 32)) {
                revert(0, 0)
            }

            // Validate return
            if iszero(eq(returndatasize(), 32)) { revert(0, 0) }
        }
    }

    /**
     * @notice Maps a field element (Fp) to a point on the G1 curve
     * @dev Calls BLS12_MAP_FP_TO_G1 precompile at address 0x10
     *
     * Memory Layout:
     * - Input: 64 bytes (Fp element)
     *   - Bytes 0-31: a0 (low 256 bits)
     *   - Bytes 32-63: a1 (high 256 bits, top 16 bytes usually zero)
     * - Output: 128 bytes (G1 point)
     *
     * Algorithm:
     * - Uses SWU (Simplified Shallue-van de Woestijne-Ulas) map-to-curve
     * - Deterministic: same input always produces same output
     * - Uniform: distribution of outputs is uniform across curve
     *
     * @param input 64 bytes encoding an Fp element (must be < field modulus)
     * @return output 128 bytes encoding the resulting G1 point
     *
     * @custom:reverts If input != 64 bytes
     * @custom:reverts If Fp element >= field modulus
     * @custom:reverts If return data size != 128 bytes
     * @custom:note Output point is always in the correct subgroup
     */
    function mapFpToG1(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            // Allocate output buffer
            output := mload(0x40)
            mstore(0x40, add(output, 0xa0))
            mstore(output, 128)

            // Execute map-to-curve
            if iszero(staticcall(gas(), MAP_FP_G1, add(input, 0x20), mload(input), add(output, 0x20), 128)) {
                revert(0, 0)
            }

            // Validate return
            if iszero(eq(returndatasize(), 128)) { revert(0, 0) }
        }
    }

    /**
     * @notice Maps a field extension element (Fp2) to a point on the G2 curve
     * @dev Calls BLS12_MAP_FP2_TO_G2 precompile at address 0x11
     *
     * Memory Layout:
     * - Input: 128 bytes (Fp2 element)
     *   - Bytes 0-63: c0 (real part as Fp)
     *   - Bytes 64-127: c1 (imaginary part as Fp)
     * - Output: 256 bytes (G2 point)
     *   - Bytes 0-127: x coordinate (Fp2)
     *   - Bytes 128-255: y coordinate (Fp2)
     *
     * Algorithm:
     * - Uses SWU map-to-curve on field extension Fp2
     * - Deterministic and uniform mapping
     *
     * Gas Cost: 23800
     *
     * @param input 128 bytes encoding an Fp2 element
     * @return output 256 bytes encoding the resulting G2 point
     *
     * @custom:reverts If input != 128 bytes
     * @custom:reverts If Fp2 element components >= field modulus
     * @custom:reverts If return data size != 256 bytes
     * @custom:note Output point is always in the correct subgroup
     */
    function mapFp2ToG2(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            // Allocate output buffer
            output := mload(0x40)
            mstore(0x40, add(output, 0x120))
            mstore(output, 256)

            // Execute map-to-curve on extension field
            if iszero(staticcall(gas(), MAP_FP2_G2, add(input, 0x20), mload(input), add(output, 0x20), 256)) {
                revert(0, 0)
            }

            // Validate return size
            if iszero(eq(returndatasize(), 256)) { revert(0, 0) }
        }
    }
}
