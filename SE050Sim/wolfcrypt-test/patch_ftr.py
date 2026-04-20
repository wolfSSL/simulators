#!/usr/bin/env python3
"""Patch fsl_sss_ftr.h to enable all EC curve features."""
import re, sys

path = sys.argv[1] if len(sys.argv) > 1 else '/app/simw-top/fsl_sss_ftr.h'
with open(path, 'r') as f:
    content = f.read()

original = content
count = 0

for feat in ['EC_NIST_192', 'EC_NIST_224', 'EC_NIST_521', 'EC_BP', 'EC_NIST_K', 'EC_MONT', 'EC_ED']:
    pattern1 = r'#\s*undef\s+SSS_HAVE_' + feat + r'\b'
    pattern2 = r'#\s*define\s+SSS_HAVE_' + feat + r'\s+0\b'
    matches1 = len(re.findall(pattern1, content))
    matches2 = len(re.findall(pattern2, content))
    if matches1 > 0 or matches2 > 0:
        print(f'  {feat}: {matches1} undefs, {matches2} zero-defines found')
        count += matches1 + matches2
    content = re.sub(pattern1, '/* undef SSS_HAVE_' + feat + ' disabled */', content)
    content = re.sub(pattern2, '#define SSS_HAVE_' + feat + ' 1 /* was 0 */', content)

# Disable HOSTCRYPTO_NONE so RSA sign paths are compiled
pattern_hcn = r'#\s*define\s+SSS_HAVE_HOSTCRYPTO_NONE\s+1\b'
if re.search(pattern_hcn, content):
    content = re.sub(pattern_hcn, '#define SSS_HAVE_HOSTCRYPTO_NONE 0 /* was 1 */', content)
    count += 1
    print('  HOSTCRYPTO_NONE: disabled')

if content != original:
    with open(path, 'w') as f:
        f.write(content)
    print(f'Patched {path}: {count} replacements made')
else:
    print(f'WARNING: No changes made to {path}!')
    # Show what lines contain the features
    for line_no, line in enumerate(original.split('\n'), 1):
        if 'SSS_HAVE_EC_NIST_224' in line:
            print(f'  Line {line_no}: {repr(line)}')
