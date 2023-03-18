from slither import Slither
from solc_select import solc_select


# Sample contract with a reentrancy vulnerability
contract_source_code = """
pragma solidity 0.7.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        require(balances[msg.sender] > 0);
        (bool successful, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(successful, "transfer failed");
        balances[msg.sender] = 0;
    }
}
"""

solc_select.switch_global_version("0.7.0", always_install=True)

# Save the contract source code to a temporary file
with open("vuln.sol", "w") as temp_file:
    temp_file.write(contract_source_code)

slither = Slither("vuln.sol")

vulnerable_contract = slither.contracts[0]

for function in vulnerable_contract.functions:
    print("####################")
    print(f'Function: {function.name}')
    print(f'  Visibility: {function.visibility}')
    print(f'  Modifiers: {", ".join([modifier.full_name for modifier in function.modifiers])}')
    print(f'  State variables read: {", ".join([var.name for var in function.state_variables_read])}')
    print(f'  State variables written: {", ".join([var.name for var in function.state_variables_written])}')
    print(f'  Is Reentrant: {str(function.is_reentrant)}')
    print("####################")
