import 'package:flutter/foundation.dart';
import 'package:oauth_flutter/oauth_flutter.dart';

void main() async {
  final client = OAuth2Client(
    key: 'fitbit',
    oauthUri: Uri.parse('https://www.fitbit.com/oauth2'),
    redirectUri: Uri.parse('https://your-app.com/oauth2/callback'),
    // Do not pass client credentials if they are injected by the server
    credentials: OAuth2ClientCredentials(
      id: 'your-client-id',
      secret: 'your-client-secret',
    ),
    scope: {'openid', 'profile'},
  );

  final token = await client.authenticate();
  debugPrint(token.idToken); // Fitbit doesn't actually support OIDC
}
