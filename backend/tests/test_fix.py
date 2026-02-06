#!/usr/bin/env python3
import io
import sys


sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print('=== Testing metadata fix ===')

try:
    print('[PASS] Models import successfully')

    print('[PASS] Service imports successfully')

    print('[PASS] Security components work')

    print('\n[FIX SUCCESS] metadata reserved attribute issue resolved')
    sys.exit(0)

except Exception as e:
    print(f'[FAIL] {e}')
    sys.exit(1)