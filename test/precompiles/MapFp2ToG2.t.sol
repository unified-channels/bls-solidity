// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

import "./PrecompileTestBase.sol";

import {BLSInternal} from "src/BLSInternal.sol";

contract MapFp2ToG2Test is PrecompileTestBase {
    function test_mapFp2ToG2_validVectors() public {
        string memory path = "test/vectors/map_fp2_to_G2_bls.json";
        string memory json = vm.readFile(path);

        CaseValid[] memory cases = abi.decode(vm.parseJson(json), (CaseValid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            vm.pauseGasMetering();
            CaseValid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));
            bytes memory expected = vm.parseBytes(string.concat("0x", _case.Expected));
            vm.resumeGasMetering();
            bytes memory result = precompiles.mapFp2ToG2(input);

            assertEq(result, expected);
        }
    }

    function test_mapFp2ToG2_internal_validVectors() public {
        string memory path = "test/vectors/map_fp2_to_G2_bls.json";
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

            BLSInternal.mapFp2ToG2(ptr);

            assembly {
                mstore(input, 256)
            }

            assertEq(input, expected);
        }
    }

    function test_mapFp2ToG2_invalidVectors() public {
        vm.pauseGasMetering();
        string memory path = "test/vectors/fail-map_fp2_to_G2_bls.json";
        string memory json = vm.readFile(path);

        CaseInvalid[] memory cases = abi.decode(vm.parseJson(json), (CaseInvalid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            CaseInvalid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));

            vm.expectRevert();
            invalidPrecompiles.mapFp2ToG2(input);
        }
    }
}
