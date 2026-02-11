// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./PrecompileTestBase.sol";

import {BlsPrecompiles} from "src/BlsPrecompiles.sol";

contract G1MulTest is PrecompileTestBase {
    function g1MSM(bytes memory input) external view returns (bytes memory result) {
        return BlsPrecompiles.g1MSM(input);
    }

    function test_g1Mul_validVectors() public {
        vm.pauseGasMetering();
        string memory path = "test/vectors/mul_G1_bls.json";
        string memory json = vm.readFile(path);

        CaseValid[] memory cases = abi.decode(vm.parseJson(json), (CaseValid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            CaseValid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));
            bytes memory expected = vm.parseBytes(string.concat("0x", _case.Expected));
            bytes memory result = this.g1MSM(input);

            assertEq(result, expected);
        }

        vm.resumeGasMetering();
    }

    function test_g1Mul_invalidVectors() public {
        vm.pauseGasMetering();
        string memory path = "test/vectors/fail-mul_G1_bls.json";
        string memory json = vm.readFile(path);

        CaseInvalid[] memory cases = abi.decode(vm.parseJson(json), (CaseInvalid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            CaseInvalid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));

            vm.expectRevert();
            this.g1MSM(input);
        }

        vm.resumeGasMetering();
    }
}
