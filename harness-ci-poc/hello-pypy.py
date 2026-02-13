#!/usr/bin/env python3
import sys
import platform
from datetime import datetime

def main():
    print("=" * 60)
    print("Hello from Harness CI Pipeline!")
    print("=" * 60)
    
    # Get pipeline inputs
    pipeline_name = sys.argv[1] if len(sys.argv) > 1 else "Unknown Pipeline"
    user_input = sys.argv[2] if len(sys.argv) > 2 else "No input provided"
    
    print(f"\nPipeline Information:")
    print(f"   Pipeline Name: {pipeline_name}")
    print(f"   User Input: {user_input}")
    print(f"   Execution Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    print(f"\nSystem Information:")
    print(f"   Python Version: {sys.version}")
    print(f"   Platform: {platform.platform()}")
    print(f"   Machine: {platform.machine()}")
    print(f"   Processor: {platform.processor()}")
    

    print("\n" + "=" * 60)
    print("Script completed successfully!")
    print("=" * 60)

if __name__ == "__main__":
    main()