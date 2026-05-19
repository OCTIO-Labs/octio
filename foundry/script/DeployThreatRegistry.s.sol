// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ThreatRegistry} from "../src/ThreatRegistry.sol";

contract DeployThreatRegistry is Script {
    function run() external returns (ThreatRegistry) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);
        
        ThreatRegistry registry = new ThreatRegistry();
        
        console.log("ThreatRegistry deployed at:", address(registry));
        console.log("Deployer:", vm.addr(deployerPrivateKey));
        
        vm.stopBroadcast();
        
        return registry;
    }
}
