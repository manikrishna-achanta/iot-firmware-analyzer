#!/usr/bin/env python3
"""
create_sample_firmware.py
Generates a synthetic firmware binary for testing iot-firmware-analyzer.
"""

import os
import gzip
import random
import struct

OUT = "samples/sample_router_fw.bin"
os.makedirs("samples", exist_ok=True)

parts = []

# 1. ELF-like header (ARM 32-bit little-endian)
elf = bytearray(64)
elf[0:4]   = b"\x7fELF"   # magic
elf[4]     = 1             # 32-bit
elf[5]     = 1             # little-endian
elf[6]     = 1             # ELF version
elf[16:18] = struct.pack("<H", 2)    # ET_EXEC
elf[18:20] = struct.pack("<H", 0x28) # ARM
parts.append(bytes(elf).ljust(512, b"\x00"))

# 2. Config / string section
config = b"""
[system]
hostname=RT-AC68U
firmware_version=3.0.0.4.386_49703

[credentials]
admin_user=admin
admin_pass=password123
backup_user=root
backup_pass=root1234
telnet_password=admin

[network]
wan_ip=192.168.1.1
lan_ip=192.168.0.1
dns_primary=8.8.8.8
update_server=http://update.routervendor.com/firmware/check

[debug]
telnet_enable=1
uart_debug=1
debug_mode=true

[remote]
api_key=sk-1a2b3c4d5e6f7890abcdef1234567890
mqtt_broker=mqtt://iot.vendorbroker.com:1883
mqtt_pass=Mqttpass2023

[update]
update_url=http://update.routervendor.com/firmware/RT-AC68U.bin
verify_signature=false
ssl_verify=0
CURLOPT_SSL_VERIFYPEER=0
"""
parts.append(config)

# 3. Dangerous function references (simulates disassembled binary strings)
code = b"""
handle_http_request: strcpy strcat sprintf gets system popen execve
upgrade_firmware: wget http://update.routervendor.com/fw.bin
debug_shell: telnetd busybox /bin/sh
crypto_init: MD5_Init SHA1_Init DES_set_key srand rand
paths: /etc/passwd /etc/shadow /var/tmp /proc/self/exe /dev/ttyS0
"""
parts.append(code)

# 4. Synthetic PEM-like block (not a real key — for testing string detection)
fake_pem = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHNOTREALKEYFORTESTING
SYNTHETICKEYBLOCKCREATEDFORTESTINGPURPOSESONLY==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDSYNTHETICCERTIFICATEFORTESTINGPURPOSESONLY========
-----END CERTIFICATE-----
"""
parts.append(fake_pem)

# 5. Gzip-compressed section
inner = b"Simulated compressed filesystem block. " * 80
gz_data = gzip.compress(inner)
parts.append(b"\nCOMPRESSED_SECTION_START\n")
parts.append(gz_data)
parts.append(b"\nCOMPRESSED_SECTION_END\n")

# 6. High-entropy block (simulates encrypted region)
random.seed(42)
encrypted_sim = bytes([random.randint(0, 255) for _ in range(2048)])
parts.append(b"\nENCRYPTED_REGION_START\n")
parts.append(encrypted_sim)
parts.append(b"\nENCRYPTED_REGION_END\n")

# 7. Extra interesting strings
misc = b"""
/proc/net/arp
NVRAM_RESET=factory_default
UART_BAUD=115200
JTAG_DEBUG_PORT=8888
remote_management_enabled=true
memcpy alloca free double-free
strncpy wcscpy vsprintf
"""
parts.append(misc)

firmware = b"".join(parts)
with open(OUT, "wb") as f:
    f.write(firmware)

print(f"[+] Sample firmware written : {OUT}")
print(f"[+] Size                    : {len(firmware):,} bytes")
print(f"\nTest with:")
print(f"  python3 firmware_analyzer.py --firmware {OUT} --all --report")
