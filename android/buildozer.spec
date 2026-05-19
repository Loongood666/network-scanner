[app]
title = Network Scanner
package.name = networkscanner
package.domain = org.netscanner
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json
version = 1.0.0
requirements = python3,kivy,pillow,cryptography,pycryptodome,urllib3,android,pyjnius
orientation = portrait

# Permissions for network scanning
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,READ_MEDIA_IMAGES,ACCESS_MEDIA_LOCATION,FOREGROUND_SERVICE,WAKE_LOCK

# For camera/brute force network operations
android.api = 30
android.minapi = 21
android.ndk = 23b
android.sdk = 30
android.ndk = 23b

# App metadata
android.arch = arm64-v8a
android.allow_backup = True
android.logcat_filters = *:S
android.gradle_dependencies = 

# Build settings
android.add_src = 
android.presplash_color = #1a1a2e

[buildozer]
log_level = 2
warn_on_root = 1