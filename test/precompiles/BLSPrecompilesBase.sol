// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

import {BLSPrecompiles} from "src/BLSPrecompiles.sol";

contract BLSPrecompilesBase {
    function g1Add(bytes memory input) external view returns (bytes memory) {
        return BLSPrecompiles.g1Add(input);
    }

    function g2Add(bytes memory input) external view returns (bytes memory) {
        return BLSPrecompiles.g2Add(input);
    }

    function g1MSM(bytes memory input) external view returns (bytes memory) {
        return BLSPrecompiles.g1MSM(input);
    }

    function g2MSM(bytes memory input) external view returns (bytes memory) {
        return BLSPrecompiles.g2MSM(input);
    }

    function pairing(bytes memory input) external view returns (bytes memory) {
        return BLSPrecompiles.pairing(input);
    }

    function mapFpToG1(bytes memory input) external view returns (bytes memory) {
        return BLSPrecompiles.mapFpToG1(input);
    }

    function mapFp2ToG2(bytes memory input) external view returns (bytes memory) {
        return BLSPrecompiles.mapFp2ToG2(input);
    }
}
