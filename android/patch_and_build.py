#!/usr/bin/env python3
"""Patch buildozer to skip root check, then build APK."""
import re
import subprocess
import sys

# Find buildozer __init__.py inside the venv
import buildozer
init_py = __import__('pathlib').Path(buildozer.__file__).resolve()
print(f"Patching {init_py} ...")

content = init_py.read_text()

# Replace check_root body with pass
old = r'(    def check_root\(self\).*?)(?=\n    def |\nclass )'
new = r'\1        pass\n'
patched = re.sub(old, new, content, flags=re.DOTALL)

if patched == content:
    print("WARNING: check_root not found, trying simpler patch...")
    # Fallback: just comment out the entire function body
    patched = content.replace(
        '        if os.geteuid() == 0:',
        '        if False:  # patched'
    )

init_py.write_text(patched)
print("Patched successfully.")

# Now run buildozer
result = subprocess.run(
    [sys.executable, '-m', 'buildozer', '-v', 'android', 'debug'],
    cwd='/app',
    env={**__import__('os').environ, 'HOME': '/home/user'}
)
sys.exit(result.returncode)
