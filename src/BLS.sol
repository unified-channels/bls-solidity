// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

import {BLSInternal} from "./BLSInternal.sol";

/**
 * @title BLS
 * @notice High-level typed wrapper for BLS12-381 curve operations via EIP-2537 precompiles
 * @dev Provides a clean, type-safe interface over BLS12-381 curve arithmetic.
 * This is the recommended entry point for most use cases.
 *
 * Architecture Overview:
 * - Zero-Copy Design: Returned structs point directly to precompile output memory
 * - Minimal allocations: Memory updated only when necessary
 * - Type safety: Solidity structs enforce correct data layout
 *
 * Memory Management:
 * - Scratch space allocated via mload(0x40) for input serialization
 * - Precompile writes output in-place (overwrites input buffer)
 * - Returned structs contain pointers to precompile output (no copying!)
 * - Free memory pointer advanced to protect precompile output
 *
 * Security Notes:
 * - All point validation performed by EIP-2537 precompiles
 * - MSM and pairing operations enforce subgroup checks
 * - Input validation: length checks on arrays, empty input rejection
 *
 * Gas Optimization:
 * - Avoids bytes memory allocation overhead
 * - No unnecessary memory copying
 * - Unchecked arithmetic in hot loops
 *
 * For raw byte-level access, see BLSPrecompiles.sol
 * For memory-pointer interface, see BLSInternal.sol
 */
library BLS {
    /// @notice Thrown when input array lengths don't match (e.g., points and scalars in MSM)
    error LengthMismatch();

    /// @notice Thrown when empty arrays provided to operations requiring at least one element
    error EmptyInput();

    /**
     * @notice Base field element Fp for BLS12-381
     * @dev Represents elements of the base field F_p where
     * p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
     *
     * Memory Layout (64 bytes):
     * - Bytes 0-31: a0 (low 256 bits)
     * - Bytes 32-63: a1 (high 125 bits, top 131 bits must be zero for valid field element)
     *
     * EIP-2537 Encoding:
     * - Big-endian format, 64 bytes total
     * - Top 16 bytes of a1 must be zero for valid encoding
     */
    struct Fp {
        uint256 a0;
        uint256 a1;
    }

    /**
     * @notice Quadratic extension field element Fp2 for BLS12-381
     * @dev Represents elements of F_p² = F_p[X]/(X² - nr2) where
     * element = c0 + c1 * v, and v² = nr2 (quadratic non-residue)
     *
     * Memory Layout (128 bytes):
     * - Bytes 0-63: c0 (real part, Fp element)
     * - Bytes 64-127: c1 (imaginary part, Fp element)
     *
     * EIP-2537 Encoding:
     * - Concatenation: encode(c0) || encode(c1)
     * - Total: 128 bytes per Fp2 element
     */
    struct Fp2 {
        Fp c0;
        Fp c1;
    }

    /**
     * @notice Point on G1 curve (short Weierstrass form over Fp)
     * @dev Represents affine point (x, y) satisfying: y² = x³ + B (mod p)
     * where B = 4 for BLS12-381
     *
     * Memory Layout (128 bytes):
     * - Bytes 0-63: x coordinate (Fp)
     * - Bytes 64-127: y coordinate (Fp)
     *
     * Point at Infinity:
     * - Encoded as 128 zero bytes (x=0, y=0)
     * - Note: (0,0) is not on the curve, used by convention
     *
     * EIP-2537 Encoding:
     * - 128 bytes: encode(x) || encode(y)
     */
    struct G1 {
        Fp x;
        Fp y;
    }

    /**
     * @notice Point on G2 curve (short Weierstrass form over Fp2)
     * @dev Represents affine point (x, y) satisfying: y² = x³ + B*(v+1) (mod Fp2)
     * G2 is the twist of G1 over the quadratic extension
     *
     * Memory Layout (256 bytes):
     * - Bytes 0-127: x coordinate (Fp2 element)
     * - Bytes 128-255: y coordinate (Fp2 element)
     *
     * Point at Infinity:
     * - Encoded as 256 zero bytes
     *
     * EIP-2537 Encoding:
     * - 256 bytes: encode(x) || encode(y)
     */
    struct G2 {
        Fp2 x;
        Fp2 y;
    }

    /**
     * @notice Scalar type for multiplication operations (element of Fr)
     * @dev Represents scalars in the prime order subgroup
     * r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
     *
     * EIP-2537 Encoding:
     * - 32 bytes, big-endian
     * - Value is NOT required to be reduced modulo r
     * - Precompile handles arbitrary 256-bit scalars
     */
    type Fr is uint256;

    /**
     * @notice Returns the generator point of G1
     * @dev The base point used for scalar multiplication in G1
     * @return G1 The generator point with coordinates as per BLS12-381 spec
     *
     * Generator Coordinates:
     * x = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
     * y = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
     */
    function g1Generator() internal pure returns (G1 memory) {
        return G1({
            x: Fp({
                a0: 31827880280837800241567138048534752271,
                a1: 88385725958748408079899006800036250932223001591707578097800747617502997169851
            }),
            y: Fp({
                a0: 11568204302792691131076548377920244452,
                a1: 114417265404584670498511149331300188430316142484413708742216858159411894806497
            })
        });
    }

    /**
     * @notice Returns the generator point of G2
     * @dev The base point used for scalar multiplication in G2
     * @return G2 The generator point with coordinates as per BLS12-381 spec
     *
     * Generator Coordinates (in Fp2):
     * x = c0 + c1*v where:
     *   c0 = 0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
     *   c1 = 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e
     * y = c0 + c1*v where:
     *   c0 = 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801
     *   c1 = 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be
     */
    function g2Generator() internal pure returns (G2 memory) {
        return G2({
            x: Fp2({
                c0: Fp({
                    a0: 3045985886519456750490515843806728273,
                    a1: 89961632905173714226157479458612185649920463576279427516307505038263245192632
                }),
                c1: Fp({
                    a0: 26419286191256893424348605754143887205,
                    a1: 40446337346877272185227670183527379362551741423616556919902061939448715946878
                })
            }),
            y: Fp2({
                c0: Fp({
                    a0: 17144095208600308495026432580569150746,
                    a1: 78698209480990513415779284580404715789311803115477290401294577488850054555649
                }),
                c1: Fp({
                    a0: 8010509799087472606393075511737879449,
                    a1: 91929332261301883145239454754739358796115486554644188311284324629555800144318
                })
            })
        });
    }

    /**
     * @notice Returns the point at infinity (identity element) in G1
     * @dev This is the additive identity: P + O = P for all P in G1
     * @return G1 The identity point (all coordinates zero)
     *
     * EIP-2537 Encoding:
     * - 128 zero bytes represents infinity
     * - Note: (0,0) is not on curve, used by convention
     */
    function g1Infinity() internal pure returns (G1 memory) {
        return G1({x: Fp({a0: 0, a1: 0}), y: Fp({a0: 0, a1: 0})});
    }

    /**
     * @notice Returns the point at infinity (identity element) in G2
     * @dev This is the additive identity: P + O = P for all P in G2
     * @return G2 The identity point (all coordinates zero)
     *
     * EIP-2537 Encoding:
     * - 256 zero bytes represents infinity
     */
    function g2Infinity() internal pure returns (G2 memory) {
        return G2({
            x: Fp2({c0: Fp({a0: 0, a1: 0}), c1: Fp({a0: 0, a1: 0})}),
            y: Fp2({c0: Fp({a0: 0, a1: 0}), c1: Fp({a0: 0, a1: 0})})
        });
    }

    /**
     * @notice Adds two points in G1
     * @dev Calls BLS12_G1ADD precompile via BLSInternal
     *
     * Memory Operations:
     * 1. Allocate 256 bytes scratch space at free memory pointer
     * 2. Serialize both G1 points (128 bytes each)
     * 3. Call precompile (overwrites first 128 bytes with result)
     * 4. Create struct pointing to result (zero-copy)
     * 5. Advance free memory pointer by 128 to protect result
     *
     * @param a First G1 point
     * @param b Second G1 point
     * @return result G1 point = a + b
     *
     * @custom:reverts If inputs are not valid G1 points
     * @custom:note No subgroup check performed
     */
    function g1Add(G1 memory a, G1 memory b) internal view returns (G1 memory result) {
        uint256 ptr;
        assembly {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 0x100))
        }

        _writeG1ToMemory(a, ptr);
        _writeG1ToMemory(b, ptr + 128);

        BLSInternal.g1Add(ptr);

        return _readG1FromMemory(ptr);
    }

    /**
     * @notice Adds two points in G2
     * @dev Calls BLS12_G2ADD precompile via BLSInternal
     *
     * Memory Operations:
     * 1. Allocate 512 bytes scratch space
     * 2. Serialize both G2 points (256 bytes each)
     * 3. Call precompile (overwrites first 256 bytes with result)
     * 4. Create struct pointing to result
     * 5. Advance free memory pointer by 256
     *
     * @param a First G2 point
     * @param b Second G2 point
     * @return result G2 point = a + b
     *
     * @custom:reverts If inputs are not valid G2 points
     * @custom:note No subgroup check performed
     */
    function g2Add(G2 memory a, G2 memory b) internal view returns (G2 memory result) {
        uint256 ptr;
        assembly {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 0x200))
        }

        _writeG2ToMemory(a, ptr);
        _writeG2ToMemory(b, ptr + 256);

        BLSInternal.g2Add(ptr);

        return _readG2FromMemory(ptr);
    }

    /**
     * @notice Computes multi-scalar multiplication in G1
     * @dev Calls BLS12_G1MSM precompile with Pippenger's algorithm
     *
     * Mathematical Operation:
     * result = scalars[0] * points[0] + scalars[1] * points[1] + ... + scalars[n-1] * points[n-1]
     *
     * Memory Layout for Precompile Input:
     * - 160 bytes per (point, scalar) pair
     * - [0-127]: G1 point
     * - [128-159]: Scalar (32 bytes, big-endian)
     *
     * @param points Array of G1 points (length must equal scalars length)
     * @param scalars Array of scalar multipliers (Fr type, length must equal points length)
     * @return result G1 point = Σ(scalars[i] * points[i])
     *
     * @custom:reverts LengthMismatch if points.length != scalars.length
     * @custom:reverts EmptyInput if arrays are empty
     * @custom:reverts If any point not on curve or not in subgroup
     * @custom:note Performs mandatory subgroup checks on all points
     */
    function g1MSM(G1[] memory points, Fr[] memory scalars) internal view returns (G1 memory result) {
        uint256 len = points.length;
        if (len != scalars.length) revert LengthMismatch();
        if (len == 0) revert EmptyInput();

        uint256 ptr;

        assembly {
            let totalSize := mul(len, 160)

            ptr := mload(0x40)
            mstore(0x40, add(ptr, totalSize))
        }

        unchecked {
            uint256 currentDest = ptr;
            for (uint256 i = 0; i < len; ++i) {
                _writeG1ToMemory(points[i], currentDest);
                uint256 s = Fr.unwrap(scalars[i]);
                assembly {
                    mstore(add(currentDest, 128), s)
                }

                currentDest += 160;
            }
        }

        BLSInternal.g1MSM(ptr, len);

        return _readG1FromMemory(ptr);
    }

    /**
     * @notice Computes multi-scalar multiplication in G2
     * @dev Calls BLS12_G2MSM precompile with Pippenger's algorithm
     *
     * Mathematical Operation:
     * result = scalars[0] * points[0] + scalars[1] * points[1] + ... + scalars[n-1] * points[n-1]
     *
     * Memory Layout for Precompile Input:
     * - 288 bytes per (point, scalar) pair
     * - [0-255]: G2 point
     * - [256-287]: Scalar (32 bytes, big-endian)
     *
     * @param points Array of G2 points (length must equal scalars length)
     * @param scalars Array of scalar multipliers (Fr type, length must equal points length)
     * @return result G2 point = Σ(scalars[i] * points[i])
     *
     * @custom:reverts LengthMismatch if points.length != scalars.length
     * @custom:reverts EmptyInput if arrays are empty
     * @custom:reverts If any point not on curve or not in subgroup
     * @custom:note Performs mandatory subgroup checks on all points
     */
    function g2MSM(G2[] memory points, Fr[] memory scalars) internal view returns (G2 memory result) {
        uint256 len = points.length;
        if (len != scalars.length) revert LengthMismatch();
        if (len == 0) revert EmptyInput();

        uint256 ptr;

        assembly {
            let totalSize := mul(len, 288)

            ptr := mload(0x40)
            mstore(0x40, add(ptr, totalSize))
        }

        unchecked {
            uint256 currentDest = ptr;

            for (uint256 i = 0; i < len; ++i) {
                _writeG2ToMemory(points[i], currentDest);
                uint256 s = Fr.unwrap(scalars[i]);

                assembly {
                    mstore(add(currentDest, 256), s)
                }

                currentDest += 288;
            }
        }

        BLSInternal.g2MSM(ptr, len);

        return _readG2FromMemory(ptr);
    }

    /**
     * @notice Verifies pairing equality: e(a[0], b[0]) * e(a[1], b[1]) * ... == 1
     * @dev Calls BLS12_PAIRING_CHECK precompile
     *
     * Mathematical Check:
     * Verifies that the product of pairings equals identity in the target group GT
     *
     * Memory Layout for Precompile Input:
     * - 384 bytes per (G1, G2) pair
     * - [0-127]: G1 point
     * - [128-383]: G2 point
     *
     * Common Use Cases:
     * - BLS signature verification: e(sig, G2) == e(msg_hash, pubkey)
     * - Aggregation verification: e(sig_agg, G2) == e(msg, pk_1) * e(msg, pk_2) * ...
     *
     * @param a Array of G1 points (length must equal b.length)
     * @param b Array of G2 points (length must equal a.length)
     * @return isValid True if pairing product equals 1, false otherwise
     *
     * @custom:reverts LengthMismatch if array lengths differ
     * @custom:reverts EmptyInput if arrays are empty
     * @custom:reverts If any point not on curve or not in subgroup
     * @custom:note All input points must be in correct subgroup
     */
    function pairing(G1[] memory a, G2[] memory b) internal view returns (bool) {
        uint256 len = a.length;
        if (len != b.length) revert LengthMismatch();
        if (len == 0) revert EmptyInput();

        uint256 ptr;

        assembly {
            let totalSize := mul(len, 384)

            ptr := mload(0x40)
            // Note: Not updating 0x40 here because we only need scratch space
            // The boolean result (32 bytes) will overwrite part of input
            // No persistent struct returned, so no need to protect memory
        }

        unchecked {
            uint256 currentDest = ptr;

            for (uint256 i = 0; i < len; ++i) {
                _writeG1ToMemory(a[i], currentDest);
                _writeG2ToMemory(b[i], currentDest + 128);

                currentDest += 384;
            }
        }

        BLSInternal.pairing(ptr, len);

        bool isValid;
        assembly {
            isValid := eq(mload(ptr), 1)
        }

        return isValid;
    }

    /**
     * @notice Maps a field element to a point on the G1 curve
     * @dev Calls BLS12_MAP_FP_TO_G1 precompile using SWU algorithm
     *
     * Algorithm:
     * - Uses Simplified Shallue-van de Woestijne-Ulas (SWU) map-to-curve
     * - Deterministic: same field element always maps to same G1 point
     * - Uniform: output distribution is uniform across G1
     *
     * Memory Operations:
     * 1. Allocate 128 bytes (64 for input, 128 for output, overlap OK)
     * 2. Copy Fp element (64 bytes)
     * 3. Call precompile (overwrites 64 bytes with 128-byte G1 point)
     * 4. Create struct pointing to result
     *
     * @param x Fp field element to map (must be < field modulus)
     * @return result G1 point on the curve
     *
     * @custom:reverts If x >= field modulus
     * @custom:note Output is always in the correct subgroup
     * @custom:warning Do NOT use for hashing to curve directly - must use expand_message first
     */
    function mapToG1(Fp memory x) internal view returns (G1 memory result) {
        uint256 ptr;

        assembly {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 128))

            mstore(ptr, mload(x))
            mstore(add(ptr, 32), mload(add(x, 32)))
        }

        BLSInternal.mapFpToG1(ptr);

        return _readG1FromMemory(ptr);
    }

    /**
     * @notice Maps a field extension element to a point on the G2 curve
     * @dev Calls BLS12_MAP_FP2_TO_G2 precompile using SWU algorithm on Fp2
     *
     * Algorithm:
     * - Uses SWU map-to-curve algorithm on quadratic extension field
     * - Deterministic and uniform mapping from Fp2 to G2
     *
     * Memory Operations:
     * 1. Allocate 256 bytes (128 for input, 256 for output, overlap OK)
     * 2. Serialize Fp2 element (128 bytes: c0 || c1)
     * 3. Call precompile (overwrites 128 bytes with 256-byte G2 point)
     * 4. Create struct hierarchy pointing to result
     *
     * @param x Fp2 field element to map (components must be < field modulus)
     * @return result G2 point on the curve
     *
     * @custom:reverts If Fp2 components >= field modulus
     * @custom:note Output is always in the correct subgroup
     * @custom:warning Do NOT use for hashing to curve directly - must use expand_message first
     */
    function mapToG2(Fp2 memory x) internal view returns (G2 memory result) {
        uint256 ptr;

        assembly {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 0x100))

            let c0_ptr := mload(x)
            let c1_ptr := mload(add(x, 32))

            mstore(ptr, mload(c0_ptr))
            mstore(add(ptr, 32), mload(add(c0_ptr, 32)))

            mstore(add(ptr, 64), mload(c1_ptr))
            mstore(add(ptr, 96), mload(add(c1_ptr, 32)))
        }

        BLSInternal.mapFp2ToG2(ptr);

        return _readG2FromMemory(ptr);
    }

    /**
     * @notice Serializes a G1 point to memory (helper function)
     * @dev Flattens G1 struct to 128 bytes at destination address
     *
     * Memory Layout Written:
     * - [dest, dest+64): x coordinate (Fp)
     * - [dest+64, dest+128): y coordinate (Fp)
     *
     * @param p G1 point to serialize
     * @param dest Memory address to write serialized data
     */
    function _writeG1ToMemory(G1 memory p, uint256 dest) internal pure {
        assembly {
            let x_ptr := mload(p)
            let y_ptr := mload(add(p, 0x20))

            mstore(dest, mload(x_ptr))
            mstore(add(dest, 0x20), mload(add(x_ptr, 0x20)))

            mstore(add(dest, 0x40), mload(y_ptr))
            mstore(add(dest, 0x60), mload(add(y_ptr, 0x20)))
        }
    }

    /**
     * @notice Creates a G1 struct pointing to memory (zero-copy helper)
     * @dev Constructs struct "skeleton" with pointers to raw coordinate data
     *
     * Zero-Copy Architecture:
     * - Does NOT copy the coordinate data
     * - Creates struct with pointers to data at `ptr`
     * - Result shares memory with precompile output
     * - Free memory pointer advanced to protect this data
     *
     * Memory Layout of Result:
     * - result: pointer to struct header (64 bytes allocated)
     * - result.x: pointer to ptr (x coordinate at ptr)
     * - result.y: pointer to ptr+64 (y coordinate at ptr+64)
     *
     * @param ptr Memory address containing 128 bytes of G1 point data
     * @return result G1 struct pointing to data at ptr
     */
    function _readG1FromMemory(uint256 ptr) internal pure returns (G1 memory result) {
        assembly {
            result := mload(0x40)
            mstore(0x40, add(result, 0x40))

            mstore(result, ptr)
            mstore(add(result, 0x20), add(ptr, 0x40))
        }
    }

    /**
     * @notice Serializes a G2 point to memory (helper function)
     * @dev Flattens G2 struct to 256 bytes at destination address
     *
     * Memory Layout Written:
     * - [dest, dest+128): x coordinate (Fp2)
     * - [dest+128, dest+256): y coordinate (Fp2)
     *
     * @param p G2 point to serialize
     * @param dest Memory address to write serialized data
     */
    function _writeG2ToMemory(G2 memory p, uint256 dest) internal pure {
        assembly {
            let x_ptr := mload(p)
            let y_ptr := mload(add(p, 0x20))

            let c0_ptr := mload(x_ptr)
            let c1_ptr := mload(add(x_ptr, 0x20))
            mstore(dest, mload(c0_ptr))
            mstore(add(dest, 0x20), mload(add(c0_ptr, 0x20)))
            mstore(add(dest, 0x40), mload(c1_ptr))
            mstore(add(dest, 0x60), mload(add(c1_ptr, 0x20)))

            c0_ptr := mload(y_ptr)
            c1_ptr := mload(add(y_ptr, 0x20))
            let y_dest := add(dest, 0x80)
            mstore(y_dest, mload(c0_ptr))
            mstore(add(y_dest, 0x20), mload(add(c0_ptr, 0x20)))
            mstore(add(y_dest, 0x40), mload(c1_ptr))
            mstore(add(y_dest, 0x60), mload(add(c1_ptr, 0x20)))
        }
    }

    /**
     * @notice Creates a G2 struct pointing to memory (zero-copy helper)
     * @dev Constructs struct hierarchy with pointers to raw coordinate data
     *
     * Zero-Copy Architecture:
     * - Does NOT copy the coordinate data
     * - Creates three-level struct hierarchy (G2 -> Fp2 -> Fp)
     * - All pointers reference data at `ptr`
     * - Result shares memory with precompile output
     *
     * Memory Layout Allocated (192 bytes total):
     * - [freeMem, freeMem+64): G2 struct header (2 Fp2 pointers)
     * - [freeMem+64, freeMem+128): x Fp2 struct (2 Fp pointers)
     * - [freeMem+128, freeMem+192): y Fp2 struct (2 Fp pointers)
     *
     * Pointer Structure:
     * - result.x -> freeMem+64 (x Fp2 struct)
     * - result.y -> freeMem+128 (y Fp2 struct)
     * - x.c0 -> ptr (x real part)
     * - x.c1 -> ptr+64 (x imaginary part)
     * - y.c0 -> ptr+128 (y real part)
     * - y.c1 -> ptr+192 (y imaginary part)
     *
     * @param ptr Memory address containing 256 bytes of G2 point data
     * @return result G2 struct hierarchy pointing to data at ptr
     */
    function _readG2FromMemory(uint256 ptr) internal pure returns (G2 memory result) {
        assembly {
            let freeMem := mload(0x40)
            mstore(0x40, add(freeMem, 0xC0))

            result := freeMem
            let x_struct := add(freeMem, 0x40)
            let y_struct := add(freeMem, 0x80)

            mstore(result, x_struct)
            mstore(add(result, 0x20), y_struct)

            mstore(x_struct, ptr)
            mstore(add(x_struct, 0x20), add(ptr, 0x40))

            mstore(y_struct, add(ptr, 0x80))
            mstore(add(y_struct, 0x20), add(ptr, 0xC0))
        }
    }
}
