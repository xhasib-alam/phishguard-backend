# PhishGuard Flutter Android App

This is the Flutter Android client for the Flask PhishGuard backend.

## Backend URL

The app default API base URL is:

```text
http://10.0.2.2:5000
```

Use this when running the app on an Android emulator and Flask is running on your PC at `127.0.0.1:5000`.

For a physical Android phone, use your computer LAN IP or deploy the backend online:

```text
http://192.168.x.x:5000
https://your-render-app.onrender.com
```

You can change the API URL inside the app from the Settings screen.

## First-Time Setup

Install Flutter first:

```powershell
flutter doctor
```

Then generate Android platform files inside this folder:

```powershell
cd C:\Users\xhasi\OneDrive\Desktop\phishing_decection\mobile\phishguard_app
flutter create --platforms android .
flutter pub get
flutter run
```

## Run Backend

From the main project folder:

```powershell
cd C:\Users\xhasi\OneDrive\Desktop\phishing_decection
.\venv\Scripts\Activate.ps1
python app.py
```

## App Features

- Register and login
- JWT bearer token storage
- URL phishing scan
- Detailed verdict, confidence, risk score, findings, recommendations
- Scan history from backend database
- Email phishing analyzer
- PDF report download/share support
- API base URL settings

