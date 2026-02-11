// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console2 as console} from "forge-std/Test.sol";
import "forge-std/StdJson.sol";

import {BlsPrecompiles} from "src/BlsPrecompiles.sol";

contract G1AddTest is Test {
    struct CaseValid {
        string Expected;
        uint256 Gas;
        string Input;
        string Name;
        bool NoBenchmark;
    }

    struct CaseInvalid {
        string ExpectedError;
        string Input;
        string Name;
    }

    function g1Add(bytes memory input) external view returns (bytes memory) {
        return BlsPrecompiles.g1Add(input);
    }

    function test_g1Add_validVectors() public view {
        string memory path = "test/vectors/add_G1_bls.json";
        string memory json = vm.readFile(path);

        CaseValid[] memory cases = abi.decode(vm.parseJson(json), (CaseValid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            CaseValid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));
            bytes memory expected = vm.parseBytes(string.concat("0x", _case.Expected));
            bytes memory result = this.g1Add(input);

            assertEq(result, expected);
        }
    }

    function test_g1Add_invalidVectors() public {
        vm.pauseGasMetering();
        string memory path = "test/vectors/fail-add_G1_bls.json";
        string memory json = vm.readFile(path);

        CaseInvalid[] memory cases = abi.decode(vm.parseJson(json), (CaseInvalid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            CaseInvalid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));

            vm.expectRevert();
            this.g1Add(input);
        }

        vm.resumeGasMetering();
    }
}
