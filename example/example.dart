import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:oauth_flutter/oauth_flutter.dart';

void main() async {
  final client = OAuth2Client(
    key: 'fitbit',
    // The `baseUrl` is the OAuth `aud` parameter
    dio: Dio(BaseOptions(baseUrl: 'https://api.fitbit.com/1/user')),
    endpoints: OAuth2Endpoints(
      authorization: 'https://fitbit.com/oauth2/authorize',
      token: 'https://api.fitbit.com/oauth2/token',
      revocation: 'https://api.fitbit.com/oauth2/revoke',
    ),
    // Use `OAuth2Endpoints.base` for services with a consistent base URL
    // endpoints: OAuth2Endpoints.base('https://api.fitbit.com/oauth2'),
    redirectUri: Uri.parse('https://your-app.com/oauth2/callback'),
    // Do not pass client credentials if they are injected by the server
    credentials: const OAuth2ClientCredentials(
      id: 'your-client-id',
      secret: 'your-client-secret',
    ),
    scope: {
      'activity',
      'heartrate',
      'nutrition',
      'oxygen_saturation',
      'respiratory_rate',
      'settings',
      'sleep',
      'temperature',
      'weight',
    },
  );

  final token = await client.authenticate();
  debugPrint(token.idToken); // Fitbit doesn't actually support OIDC

  final response =
      await client.dio.get('/GGNJL9/activities/heart/date/today/1d.json');
  debugPrint(response.data);

  final isAuthenticated = await client.isAuthenticated();
  debugPrint(isAuthenticated.toString());
}
