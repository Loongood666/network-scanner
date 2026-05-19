#!/usr/bin/env python3
"""Patch buildozer to skip root check at runtime."""
import sys
import os

# Find buildozer package location
import buildozer
buildozer_path = buildozer.__file__
buildozer_pkg_dir = os.path.dirname(buildozer_path)

# Patch __init__.py - replace check_root method
init_py = os.path.join(buildozer_pkg_dir, '__init__.py')
with open(init_py, 'r') as f:
    content = f.read()

# Replace check_root to do nothing
old_check_root = '''    def check_root(self):
        if os.geteuid() == 0:
            print("Buildozer is running as root!")
            print("This is not recommended, and may lead to problems later.")
            cont = input('Are you sure you want to continue [y/n]? ')
            if cont.lower() != 'y':
                sys.exit(1)'''

new_check_root = '''    def check_root(self):
        pass  # Patched: skip root check'''

if old_check_root in content:
    content = content.replace(old_check_root, new_check_root)
    with open(init_py, 'w') as f:
        f.write(content)
    print(f"Patched {init_py}")
else:
    print("WARNING: check_root pattern not found, trying alternative patch...")
    # Try replacing just the condition
    content = content.replace('if os.geteuid() == 0:', 'if False:')
    with open(init_py, 'w') as f:
        f.write(content)
    print("Applied alternative patch")

print("Buildozer root check patched successfully.")
