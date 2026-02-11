// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library BlsPrecompiles {
    /// @dev EIP-2537 precompile: G1 addition
    uint256 internal constant G1_ADD = 0x0b;

    /// @dev EIP-2537 precompile: G1 multi scalar multiplication
    uint256 internal constant G1_MSM = 0x0c;

    /// @dev EIP-2537 precompile: G2 addition
    uint256 internal constant G2_ADD = 0x0d;

    /// @dev EIP-2537 precompile: G2 multi scalar multiplication
    uint256 internal constant G2_MSM = 0x0e;

    /// @dev EIP-2537 precompile: Pairing check
    uint256 internal constant PAIRING = 0x0f;

    /// @dev EIP-2537 precompile: Fp → G1 mapping
    uint256 internal constant MAP_FP_G1 = 0x10;

    /// @dev EIP-2537 precompile: Fp2 → G2 mapping
    uint256 internal constant MAP_FP2_G2 = 0x11;

    /**
     * @notice Calls the BLS12_G1ADD precompile.
     * @dev
     * Input must be 256 bytes:
     * - 128 bytes G1 point
     * - 128 bytes G1 point
     *
     * Output is 128 bytes:
     * - G1 point
     *
     * Reverts if:
     * - Precompile execution fails
     * - Return size != 128 bytes
     *
     * This function does NOT validate input length or encoding.
     */
    function g1Add(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            // Allocate 160 bytes (32 length + 128 data)
            output := mload(0x40)
            mstore(0x40, add(output, 0xa0))
            mstore(output, 128)

            // Call precompile
            if iszero(staticcall(gas(), G1_ADD, add(input, 0x20), mload(input), add(output, 0x20), 128)) {
                revert(0, 0)
            }

            // Defensive return-size check
            if iszero(eq(returndatasize(), 128)) { revert(0, 0) }
        }
    }

    /**
     * @notice Calls the BLS12_G2ADD precompile.
     * @dev
     * Input must be 512 bytes, two G2 points
     *
     * Output is 256 bytes:
     * - G2 point
     */
    function g2Add(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            // Allocate 288 bytes (32 length + 256 data)
            output := mload(0x40)
            mstore(0x40, add(output, 0x120))
            mstore(output, 256)

            // Call precompile
            if iszero(staticcall(gas(), G2_ADD, add(input, 0x20), mload(input), add(output, 0x20), 256)) {
                revert(0, 0)
            }

            // Defensive return-size check
            if iszero(eq(returndatasize(), 256)) { revert(0, 0) }
        }
    }

    /**
     * @notice Calls the BLS12_G1MSM precompile.
     * @dev
     * Input must be 160 * k bytes (k >= 1).
     *
     * Output is 128 bytes:
     * - G1 point
     */
    function g1MSM(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            output := mload(0x40)
            mstore(0x40, add(output, 0xa0))
            mstore(output, 128)

            if iszero(staticcall(gas(), G1_MSM, add(input, 0x20), mload(input), add(output, 0x20), 128)) {
                revert(0, 0)
            }

            if iszero(eq(returndatasize(), 128)) { revert(0, 0) }
        }
    }

    /**
     * @notice Calls the BLS12_G2MSM precompile.
     * @dev
     * Input must be 288 * k bytes (k >= 1).
     *
     * Output is 256 bytes:
     * - G2 point
     */
    function g2MSM(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            output := mload(0x40)
            mstore(0x40, add(output, 0x120))
            mstore(output, 256)

            if iszero(staticcall(gas(), G2_MSM, add(input, 0x20), mload(input), add(output, 0x20), 256)) {
                revert(0, 0)
            }

            if iszero(eq(returndatasize(), 256)) { revert(0, 0) }
        }
    }

    /**
     * @notice Calls the BLS12_PAIRING_CHECK precompile.
     * @dev
     * Input must be 384 * k bytes (k >= 1).
     *
     * Output is 32 bytes:
     * - Last byte is 0x01 if pairing holds, 0x00 otherwise
     */
    function pairing(bytes memory input) internal view returns (bool result) {
        bytes memory out;

        assembly {
            out := mload(0x40)
            mstore(0x40, add(out, 0x40))
            mstore(out, 32)

            if iszero(staticcall(gas(), PAIRING, add(input, 0x20), mload(input), add(out, 0x20), 32)) { revert(0, 0) }

            if iszero(eq(returndatasize(), 32)) { revert(0, 0) }
        }

        assembly {
            result := eq(byte(31, mload(add(out, 0x20))), 1)
        }
    }

    /**
     * @notice Calls the BLS12_MAP_FP_TO_G1 precompile.
     * @dev
     * Input must be 64 bytes
     *
     * Output is 128 bytes:
     * - G1 point
     */
    function mapFpToG1(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            output := mload(0x40)
            mstore(0x40, add(output, 0xa0))
            mstore(output, 128)

            if iszero(staticcall(gas(), MAP_FP_G1, add(input, 0x20), mload(input), add(output, 0x20), 128)) {
                revert(0, 0)
            }

            if iszero(eq(returndatasize(), 128)) { revert(0, 0) }
        }
    }

    /**
     * @notice Calls the BLS12_MAP_FP2_TO_G2 precompile.
     * @dev
     * Input must be 128 bytes
     *
     * Output is 256 bytes:
     * - G2 point
     */
    function mapFp2ToG2(bytes memory input) internal view returns (bytes memory output) {
        assembly {
            output := mload(0x40)
            mstore(0x40, add(output, 0x120))
            mstore(output, 256)

            if iszero(staticcall(gas(), MAP_FP2_G2, add(input, 0x20), mload(input), add(output, 0x20), 256)) {
                revert(0, 0)
            }

            if iszero(eq(returndatasize(), 256)) { revert(0, 0) }
        }
    }
}
