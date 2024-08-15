A drop-in OAuth2 solution for Flutter apps. Handles auth, token storage, and token refresh.

## Features

- Handles `dio` client setup
- Securely stores tokens
- Automatically refreshes tokens when expired
- Optional handler for token refresh failures. Defaults to re-authenticating the user.

## Getting started

The most relevant setup information for iOS/Android/web apps is copied below. See the individual plugin readmes for more details:

- [flutter_web_auth_2](https://pub.dev/packages/flutter_web_auth_2)
- [flutter_secure_storage](https://pub.dev/packages/flutter_secure_storage)

### iOS

Recommended:
To authenticate using [Universal Links](https://developer.apple.com/library/archive/documentation/General/Conceptual/AppSearch/UniversalLinks.html)
on iOS, use `https` as the provided `callbackUrlScheme`.

### Android

`android/app/build.gradle`

```kotlin
android {
    defaultConfig {
        minSdk = 23
    }
}
```

In order to capture the callback url, the following activity needs to be added to your `AndroidManifest.xml`. Be sure to replace `YOUR_CALLBACK_URL_SCHEME_HERE` with your actual callback url scheme.

```xml
<manifest>
  <application>

    <activity
      android:name="com.linusu.flutter_web_auth_2.CallbackActivity"
      android:exported="true">
      <intent-filter android:label="flutter_web_auth_2">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="YOUR_CALLBACK_URL_SCHEME_HERE" />
      </intent-filter>
    </activity>

  </application>
</manifest>
```

### Web

Ensure that the web server serves the Flutter app with a `Strict-Transport-Security` header. Firebase Hosting sets this header by default. See [the documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security). Here is an example header:

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

An endpoint must be created that captures the callback URL and sends it to the application using the JavaScript `postMessage` method. In the `web` folder of the project, create an HTML file named, e.g. `auth.html` with content:

```html
<!DOCTYPE html>
<title>Authentication complete</title>
<p>
  Authentication is complete. If this does not happen automatically, please
  close the window.
</p>
<script>
  function postAuthenticationMessage() {
    const message = {
      "flutter-web-auth-2": window.location.href,
    };

    if (window.opener) {
      window.opener.postMessage(message, window.location.origin);
      window.close();
    } else if (window.parent && window.parent !== window) {
      window.parent.postMessage(message, window.location.origin);
    } else {
      localStorage.setItem("flutter-web-auth-2", window.location.href);
      window.close();
    }
  }

  postAuthenticationMessage();
</script>
```

## Usage

TODO: Include short and useful examples for package users. Add longer examples
to `/example` folder.

```dart
const like = 'sample';
```

## Additional information

TODO: Tell users more about the package: where to find more information, how to
contribute to the package, how to file issues, what response they can expect
from the package authors, and more.
