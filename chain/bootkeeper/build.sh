#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SDK="${ANDROID_SDK:-/opt/homebrew/share/android-commandlinetools}"
BT="$(ls -d "$SDK"/build-tools/*/ | sort -V | tail -1)"
PLATFORM="${PLATFORM:-android-27}"
AJ="$SDK/platforms/$PLATFORM/android.jar"

for f in "$BT/aapt2" "$BT/d8" "$BT/zipalign" "$BT/apksigner" "$AJ"; do
    [ -e "$f" ] || { echo "missing: $f" >&2; exit 1; }
done

OUT="$HERE/out"
CLS="$OUT/classes"
rm -rf "$OUT"
mkdir -p "$CLS" "$OUT/gen" "$OUT/dex"

"$BT/aapt2" compile --dir "$HERE/res" -o "$OUT/res.zip"
"$BT/aapt2" link \
      -o "$OUT/base.apk" \
      -I "$AJ" \
      --manifest "$HERE/AndroidManifest.xml" \
      --java "$OUT/gen" \
      --min-sdk-version 21 --target-sdk-version 27 \
      "$OUT/res.zip"

javac -source 8 -target 8 -nowarn \
      -bootclasspath "$AJ" -classpath "$AJ" \
      -d "$CLS" \
      $(find "$HERE/src" "$OUT/gen" -name '*.java')

"$BT/d8" --min-api 21 --lib "$AJ" --output "$OUT/dex" \
      $(find "$CLS" -name '*.class')

(cd "$OUT/dex" && zip -q -j "$OUT/base.apk" classes.dex)
"$BT/zipalign" -f -p 4 "$OUT/base.apk" "$OUT/aligned.apk"

KS="$OUT/ks.jks"
if [ ! -f "$KS" ]; then
    keytool -genkeypair -keystore "$KS" -alias bk \
            -keyalg RSA -keysize 2048 -validity 10000 \
            -storepass android -keypass android \
            -dname "CN=MHBootKeeper, O=MH, C=ES" >/dev/null 2>&1
fi
"$BT/apksigner" sign \
      --ks "$KS" --ks-pass pass:android --key-pass pass:android \
      --v1-signing-enabled true --v2-signing-enabled true \
      --out "$HERE/BootKeeper.apk" "$OUT/aligned.apk"

echo
ls -l "$HERE/BootKeeper.apk"