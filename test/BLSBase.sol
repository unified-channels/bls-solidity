// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

import {BLS} from "src/BLS.sol";

import {console2 as console} from "forge-std/console2.sol";

contract BLSBase {
    function g1Add(BLS.G1 memory a, BLS.G1 memory b) external view returns (BLS.G1 memory result) {
        return BLS.g1Add(a, b);
    }

    function g2Add(BLS.G2 memory a, BLS.G2 memory b) external view returns (BLS.G2 memory result) {
        return BLS.g2Add(a, b);
    }

    function g1MSM(BLS.G1[] memory points, BLS.Fr[] memory scalars) external view returns (BLS.G1 memory result) {
        return BLS.g1MSM(points, scalars);
    }

    function g2MSM(BLS.G2[] memory points, BLS.Fr[] memory scalars) external view returns (BLS.G2 memory result) {
        return BLS.g2MSM(points, scalars);
    }

    function pairing(BLS.G1[] memory a, BLS.G2[] memory b) external view returns (bool) {
        return BLS.pairing(a, b);
    }

    function mapToG1(BLS.Fp memory x) external view returns (BLS.G1 memory result) {
        return BLS.mapToG1(x);
    }

    function mapToG2(BLS.Fp2 memory x) external view returns (BLS.G2 memory result) {
        return BLS.mapToG2(x);
    }
}
