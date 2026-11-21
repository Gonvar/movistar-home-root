#!/bin/bash
# Build MH-Agent.apk: the boot-persistent agent (see src/com/mh/agent/).
#
# Signed with the AOSP testkey, same as MH-Helper.  That is enough here: this is an
# ordinary app.  It does NOT need platform identity -- which is just as well, because
# this ROM's platform key is Askey's own 2048-bit key, not a test key.
set -e
SDK=/opt/homebrew/share/android-commandlinetools
BT=$SDK/build-tools/34.0.0
JAR=$SDK/platforms/android-27/android.jar
cd "$(dirname "$0")"
rm -rf build && mkdir -p build/classes build/apk

echo "[1/5] aapt2: manifest -> base.apk"
$BT/aapt2 link --manifest AndroidManifest.xml -I "$JAR" \
    --min-sdk-version 21 --target-sdk-version 25 \
    --version-code 4 --version-name 4.0 \
    -o build/base.apk

echo "[2/5] javac"
javac -source 1.8 -target 1.8 -nowarn -cp "$JAR" -d build/classes \
    src/com/mh/agent/*.java

echo "[3/5] d8 -> classes.dex"
$BT/d8 --release --lib "$JAR" --min-api 21 \
    --output build/apk \
    build/classes/com/mh/agent/*.class

echo "[4/5] pack dex into apk"
(cd build/apk && zip -q -X ../base.apk classes.dex)

echo "[5/5] zipalign + apksigner (AOSP testkey)"
$BT/zipalign -f 4 build/base.apk build/aligned.apk
$BT/apksigner sign --key ../keys/testkey.pk8 --cert ../keys/testkey.x509.pem \
    --out ../MH-Agent.apk build/aligned.apk
ls -la ../MH-Agent.apk
echo DONE
