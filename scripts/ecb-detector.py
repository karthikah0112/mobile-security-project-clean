#!/usr/bin/env python3
"""
ecb-detector.py — Detect AES-ECB mode via block pattern analysis
Finding: F-006 — AES-ECB mode used for local data encryption
Usage: python3 scripts/ecb-detector.py <binary_file>

ECB mode is insecure because identical plaintext blocks always produce
identical ciphertext blocks, leaking patterns in the data.
"""

import sys
import os
import collections


def detect_ecb(data: bytes, block_size: int = 16) -> dict:
    """Analyse binary data for AES-ECB block repetitions."""
    blocks = [data[i:i + block_size] for i in range(0, len(data) - block_size + 1, block_size)]
    counter = collections.Counter(blocks)
    duplicates = {k: v for k, v in counter.items() if v > 1}
    return {
        'total_blocks': len(blocks),
        'unique_blocks': len(counter),
        'duplicate_blocks': len(duplicates),
        'duplicates': duplicates,
        'ecb_likely': len(duplicates) > 0,
    }


def hex_preview(b: bytes, n: int = 16) -> str:
    return b[:n].hex() + ('...' if len(b) > n else '')


def main():
    if len(sys.argv) < 2:
        print('Usage: python3 scripts/ecb-detector.py <file>')
        print('Example: python3 scripts/ecb-detector.py api_cache.bin')
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f'[!] File not found: {filepath}')
        sys.exit(1)

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f'\n[F-006] ECB Block Pattern Detector')
    print(f'[F-006] File: {filepath} ({len(data)} bytes)')
    print(f'[F-006] {"-" * 50}')

    for block_size in [16, 8, 32]:
        result = detect_ecb(data, block_size)
        print(f'\n[F-006] Block size: {block_size} bytes ({block_size * 8} bits)')
        print(f'[F-006]   Total blocks:     {result["total_blocks"]}')
        print(f'[F-006]   Unique blocks:    {result["unique_blocks"]}')
        print(f'[F-006]   Duplicate blocks: {result["duplicate_blocks"]}')

        if result['ecb_likely']:
            print(f'[F-006]   ⚠️  POSSIBLE ECB MODE — repeated blocks detected!')
            print(f'[F-006]   Repeated blocks:')
            for block, count in sorted(result['duplicates'].items(), key=lambda x: -x[1])[:5]:
                print(f'[F-006]     {block.hex()}  →  appears {count} times')
        else:
            print(f'[F-006]   ✅  No repeating blocks found at this block size')

    # Also check for high byte frequency (another ECB indicator)
    byte_freq = collections.Counter(data)
    most_common = byte_freq.most_common(3)
    print(f'\n[F-006] Byte frequency analysis (top 3):')
    for byte, count in most_common:
        pct = count / len(data) * 100
        print(f'[F-006]   0x{byte:02x} ({byte:3d}): {count} occurrences ({pct:.1f}%)')
        if pct > 15:
            print(f'[F-006]   ⚠️  High byte frequency may indicate weak or no encryption')

    print(f'\n[F-006] Done.\n')


if __name__ == '__main__':
    main()
