xcodebuild clean build -sdk iphoneos -project "kfd.xcodeproj" -configuration Release CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED="NO"
cd build/Release-iphoneos
rm -rf Payload
rm -rf FUCK.tipa
mkdir Payload
cp -r kfd.app Payload
zip -vr kfdtsinstall.tipa Payload/ -x "*.DS_Store"
echo "done building"
open .