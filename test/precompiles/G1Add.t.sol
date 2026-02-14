// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

import "./PrecompileTestBase.sol";
import {BLSInternal} from "src/BLSInternal.sol";
import {BLSPrecompiles} from "src/BLSPrecompiles.sol";

contract G1AddTest is PrecompileTestBase {
    function test_g1Add_validVectors() public view {
        string memory path = "test/vectors/add_G1_bls.json";
        string memory json = vm.readFile(path);

        CaseValid[] memory cases = abi.decode(vm.parseJson(json), (CaseValid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            CaseValid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));
            bytes memory expected = vm.parseBytes(string.concat("0x", _case.Expected));
            bytes memory result = precompiles.g1Add(input);

            assertEq(result, expected);
        }
    }

    function test_g1Add_internal_validVectors() public view {
        string memory path = "test/vectors/add_G1_bls.json";
        string memory json = vm.readFile(path);

        CaseValid[] memory cases = abi.decode(vm.parseJson(json), (CaseValid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            CaseValid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));
            bytes memory expected = vm.parseBytes(string.concat("0x", _case.Expected));

            uint256 ptr;
            assembly {
                ptr := add(input, 0x20)
            }

            BLSInternal.g1Add(ptr);

            assembly {
                mstore(input, 128)
            }

            assertEq(input, expected);
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
            invalidPrecompiles.g1Add(input);
        }
    }
}
