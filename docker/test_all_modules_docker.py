#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from tool_manager import create_default_tool_manager
from modules.exploit_module import generate_reverse_shell_payload, adapt_exploit_template
from modules.osint_module import osint_search
from modules.network_module import network_scan
from modules.password_module import password_crack
from modules.analysis_module import code_analysis

def test_all_modules():
    print('=== Testing All Modules in Docker Environment ===')
    
    # Test ToolManager with all modules
    tool_manager = create_default_tool_manager()
    print(f'ToolManager registered tools: {list(tool_manager.tools.keys())}')
    print(f'Total tools registered: {len(tool_manager.tools)}')
    
    # Test exploit module
    print('\n--- Testing Exploit Module ---')
    result = generate_reverse_shell_payload('192.168.1.100', 4444, 'python')
    print(f'Reverse shell generation: {result["success"]}')
    
    # Test OSINT module
    print('\n--- Testing OSINT Module ---')
    try:
        result = osint_search('example.com')
        print(f'OSINT search: {result["success"]}')
    except Exception as e:
        print(f'OSINT search error: {e}')
    
    # Test network module
    print('\n--- Testing Network Module ---')
    try:
        result = network_scan('127.0.0.1')
        print(f'Network scan: {result["success"]}')
    except Exception as e:
        print(f'Network scan error: {e}')
    
    # Test password module
    print('\n--- Testing Password Module ---')
    try:
        result = password_crack('5f4dcc3b5aa765d61d8327deb882cf99', 'md5')
        print(f'Password crack: {result["success"]}')
    except Exception as e:
        print(f'Password crack error: {e}')
    
    # Test analysis module
    print('\n--- Testing Analysis Module ---')
    try:
        result = code_analysis('/app/test_code.py')
        print(f'Code analysis: {result["success"]}')
    except Exception as e:
        print(f'Code analysis error: {e}')
    
    # Test ToolManager exploit functions
    print('\n--- Testing ToolManager Exploit Functions ---')
    try:
        result = tool_manager.execute_tool('generate_reverse_shell_payload', {
            'ip': '192.168.1.100',
            'port': 4444,
            'language': 'python'
        })
        print(f'ToolManager reverse shell: {result["success"]}')
    except Exception as e:
        print(f'ToolManager reverse shell error: {e}')
    
    print('\n=== All Modules Docker Test Complete ===')

if __name__ == "__main__":
    test_all_modules()
