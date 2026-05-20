import os, subprocess

sdk_root = os.path.expanduser("~/.buildozer/android/platform/android-sdk")

# 验证文件存在
sdkmanager = f"{sdk_root}/tools/bin/sdkmanager"
print(f"sdkmanager exists: {os.path.exists(sdkmanager)}")

# 尝试运行（stderr 也捕获）
result = subprocess.run(
    [sdkmanager, "--version"],
    capture_output=True, text=True, timeout=10
)
print(f"stdout: {result.stdout.strip()}")
print(f"stderr: {result.stderr.strip()}")

# 同时验证 lib 目录
lib_dir = f"{sdk_root}/tools/lib"
print(f"tools/lib exists: {os.path.exists(lib_dir)}")
if os.path.exists(lib_dir):
    print(f"tools/lib contents: {os.listdir(lib_dir)[:5]}")
