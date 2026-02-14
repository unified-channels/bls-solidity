// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

import "./PrecompileTestBase.sol";

import {BLSInternal} from "src/BLSInternal.sol";

contract MapFpToG1Test is PrecompileTestBase {
    function test_mapFpToG1_validVectors() public {
        string memory path = "test/vectors/map_fp_to_G1_bls.json";
        string memory json = vm.readFile(path);

        CaseValid[] memory cases = abi.decode(vm.parseJson(json), (CaseValid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            vm.pauseGasMetering();
            CaseValid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));
            bytes memory expected = vm.parseBytes(string.concat("0x", _case.Expected));
            vm.resumeGasMetering();
            bytes memory result = precompiles.mapFpToG1(input);

            assertEq(result, expected);
        }
    }

    function test_mapFpToG1_internal_validVectors() public {
        string memory path = "test/vectors/map_fp_to_G1_bls.json";
        string memory json = vm.readFile(path);

        CaseValid[] memory cases = abi.decode(vm.parseJson(json), (CaseValid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            vm.pauseGasMetering();
            CaseValid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));
            bytes memory expected = vm.parseBytes(string.concat("0x", _case.Expected));
            vm.resumeGasMetering();

            uint256 ptr;
            assembly {
                ptr := add(input, 0x20)
            }

            BLSInternal.mapFpToG1(ptr);

            assembly {
                mstore(input, 128)
            }

            assertEq(input, expected);
        }
    }

    function test_mapFpToG1_invalidVectors() public {
        vm.pauseGasMetering();
        string memory path = "test/vectors/fail-map_fp_to_G1_bls.json";
        string memory json = vm.readFile(path);

        CaseInvalid[] memory cases = abi.decode(vm.parseJson(json), (CaseInvalid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            CaseInvalid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));

            vm.expectRevert();
            invalidPrecompiles.mapFpToG1(input);
        }
    }
}
