// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.3;

import "forge-std/Test.sol";
import "../src/LayerLightClientBridge.sol";

contract CounterTest is Test {
    LayerLightClientBridge public bridge;

    function setUp() public {
        bridge = new LayerLightClientBridge();
        bridge.testSetNumber(0);
    }

    function testSetNumber(uint256 x) public {
        bridge.testSetNumber(x);
        assertEq(bridge.testNumber(), x);
    }
}
