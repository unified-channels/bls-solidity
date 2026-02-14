// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

import "./PrecompileTestBase.sol";

import {BLSInternal} from "src/BLSInternal.sol";

contract G2MSMTest is PrecompileTestBase {
    function test_g2Msm_validVectors() public {
        vm.pauseGasMetering();
        string memory path = "test/vectors/msm_G2_bls.json";
        string memory json = vm.readFile(path);

        CaseValid[] memory cases = abi.decode(vm.parseJson(json), (CaseValid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            vm.pauseGasMetering();
            CaseValid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));
            bytes memory expected = vm.parseBytes(string.concat("0x", _case.Expected));
            vm.resumeGasMetering();
            bytes memory result = precompiles.g2MSM(input);

            assertEq(result, expected);
        }

        vm.resumeGasMetering();
    }

    function test_g2Msm_internal_validVectors() public {
        vm.pauseGasMetering();
        string memory path = "test/vectors/msm_G2_bls.json";
        string memory json = vm.readFile(path);

        CaseValid[] memory cases = abi.decode(vm.parseJson(json), (CaseValid[]));
        vm.resumeGasMetering();

        for (uint256 i = 0; i < cases.length; i++) {
            vm.pauseGasMetering();
            CaseValid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));
            bytes memory expected = vm.parseBytes(string.concat("0x", _case.Expected));

            vm.resumeGasMetering();

            uint256 len = input.length / 288;

            uint256 ptr;
            assembly {
                ptr := add(input, 0x20)
            }

            BLSInternal.g2MSM(ptr, len);

            assembly {
                mstore(input, 256)
            }

            assertEq(input, expected);
        }
        vm.resumeGasMetering();
    }

    function test_g2Msm_invalidVectors() public {
        vm.pauseGasMetering();
        string memory path = "test/vectors/fail-msm_G2_bls.json";
        string memory json = vm.readFile(path);

        CaseInvalid[] memory cases = abi.decode(vm.parseJson(json), (CaseInvalid[]));

        for (uint256 i = 0; i < cases.length; i++) {
            CaseInvalid memory _case = cases[i];
            bytes memory input = vm.parseBytes(string.concat("0x", _case.Input));

            vm.expectRevert();
            invalidPrecompiles.g2MSM(input);
        }
    }
}
