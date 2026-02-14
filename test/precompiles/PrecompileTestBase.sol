// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30 <0.9.0;

import {Test} from "forge-std/Test.sol";

import {BLSPrecompilesBase} from "./BLSPrecompilesBase.sol";

contract BLSPrecompilesInvalidBase is BLSPrecompilesBase {}

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

contract PrecompileTestBase is Test {
    BLSPrecompilesBase public precompiles;
    BLSPrecompilesInvalidBase public invalidPrecompiles;

    function setUp() public virtual {
        precompiles = new BLSPrecompilesBase();
        invalidPrecompiles = new BLSPrecompilesInvalidBase();
    }
}
