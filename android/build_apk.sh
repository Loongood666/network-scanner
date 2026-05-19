#!/bin/bash
set -e

echo "=== Network Scanner APK Build Script ==="
echo ""

# 检查是否在 android 目录
if [ ! -f "buildozer.spec" ]; then
    echo "ERROR: buildozer.spec not found!"
    echo "Please run this script from the android/ directory"
    exit 1
fi

echo "[1/5] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3-pip python3-dev python3-venv git zip unzip openjdk-17-jdk \
    libbz2-dev libncurses5-dev libffi-dev libreadline-dev libsqlite3-dev \
    zlib1g-dev liblzma-dev autoconf libtool pkg-config python3-setuptools \
    wget curl build-essential

echo ""
echo "[2/5] Installing Cython and Buildozer..."
pip3 install --user cython==0.29.19
pip3 install --user buildozer
export PATH="$HOME/.local/bin:$PATH"

echo ""
echo "[3/5] Setting up Android SDK..."
mkdir -p $HOME/android-sdk/cmdline-tools
cd $HOME/android-sdk/cmdline-tools
wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip -q commandlinetools-linux-11076708_latest.zip
mv cmdline-tools latest
export ANDROID_SDK_ROOT=$HOME/android-sdk
export ANDROID_HOME=$HOME/android-sdk
export PATH="$PATH:$HOME/android-sdk/cmdline-tools/latest/bin:$HOME/android-sdk/platform-tools"

echo ""
echo "[4/5] Installing Android SDK components (this may take a while)..."
yes | sdkmanager --licenses > /dev/null 2>&1 || true
sdkmanager "platform-tools" "platforms;android-30" "build-tools;30.0.3"

echo ""
echo "[5/5] Building APK (this will take 30-60 minutes)..."
cd -
buildozer -v android debug

echo ""
echo "=== BUILD COMPLETE ==="
if [ -f "bin/*.apk" ]; then
    echo "APK found:"
    ls -lh bin/*.apk
    echo ""
    echo "You can download the APK from: $(pwd)/bin/"
else
    echo "ERROR: APK not found. Check the build log above."
    exit 1
fi
