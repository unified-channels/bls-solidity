// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./PrecompileTestBase.sol";

import {BlsPrecompiles} from "src/BlsPrecompiles.sol";

contract G2AddTest is PrecompileTestBase {
    function g2Add(bytes memory input) external view returns (bytes memory result) {
        return BlsPrecompiles.g2Add(input);
    }

    function test_g2Add_validVectors() public view {
        string memory path = "test/vectors/add_G2_bls.json";
        string memory json = vm.readFile(path);

        CaseValid[] memory cases = abi.decode(vm.parseJson(json), (CaseValid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            CaseValid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));
            bytes memory expected = vm.parseBytes(string.concat("0x", _case.Expected));
            bytes memory result = this.g2Add(input);

            assertEq(result, expected);
        }
    }

    function test_g2Add_invalidVectors() public {
        vm.pauseGasMetering();
        string memory path = "test/vectors/fail-add_G2_bls.json";
        string memory json = vm.readFile(path);

        CaseInvalid[] memory cases = abi.decode(vm.parseJson(json), (CaseInvalid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            CaseInvalid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));

            vm.expectRevert();
            this.g2Add(input);
        }

        vm.resumeGasMetering();
    }
}
