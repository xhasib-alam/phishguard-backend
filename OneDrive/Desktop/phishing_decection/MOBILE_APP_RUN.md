# How To Run The PhishGuard Flutter Android App

The Flutter app source is located at:

```text
C:\Users\xhasi\OneDrive\Desktop\phishing_decection\mobile\phishguard_app
```

## 1. Install Flutter

Install Flutter from:

```text
https://docs.flutter.dev/get-started/install/windows/mobile
```

Then verify:

```powershell
flutter doctor
```

Fix anything Flutter reports for Android Studio, Android SDK, or licenses.

## 2. Start The Flask Backend

Open PowerShell:

```powershell
cd C:\Users\xhasi\OneDrive\Desktop\phishing_decection
.\venv\Scripts\Activate.ps1
python app.py
```

Keep this running.

## 3. Generate Android Project Files

Because Flutter is not currently available on this machine PATH, the app source has been created manually. After installing Flutter, run:

```powershell
cd C:\Users\xhasi\OneDrive\Desktop\phishing_decection\mobile\phishguard_app
flutter create --platforms android .
flutter pub get
```

## 4. Run On Android Emulator

Start an Android emulator from Android Studio, then run:

```powershell
flutter run
```

The app default API URL is:

```text
http://10.0.2.2:5000
```

That points from the Android emulator to your PC Flask server.

## 5. Run On A Real Android Phone

Your phone cannot use `127.0.0.1` or `10.0.2.2` to reach your PC.

Use one of these:

1. Deploy Flask backend online using Render/Railway/VPS.
2. Use your PC LAN IP, for example:

```text
http://192.168.1.5:5000
```

Then open the app:

```text
Settings -> Backend API -> Base URL
```

Save the correct URL.

## 6. Build APK

```powershell
flutter build apk --release
```

APK output:

```text
build\app\outputs\flutter-apk\app-release.apk
```

## App Features

- URL phishing scanner
- Risk score and confidence
- Detailed findings and recommendations
- PDF report download/share
- Backend scan history
- Email phishing analyzer
- Login/register with token storage
- Configurable backend API URL

