import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:oauth_flutter/oauth_flutter.dart';

void main() async {
  final client = OAuth2Client(
    key: 'fitbit',
    dio: Dio(BaseOptions(baseUrl: 'https://api.fitbit.com/1/user')),
    authorizationUri: Uri.parse('https://www.fitbit.com/oauth2/authorize'),
    tokenUri: Uri.parse('https://api.fitbit.com/oauth2/token'),
    redirectUri: Uri.parse('https://your-app.com/oauth2/callback'),
    // Do not pass client credentials if they are injected by the server
    credentials: const OAuth2ClientCredentials(
      id: 'your-client-id',
      secret: 'your-client-secret',
    ),
    scope: {},
  );

  final token = await client.authenticate();
  debugPrint(token.idToken); // Fitbit doesn't actually support OIDC

  final response =
      await client.dio.get('/GGNJL9/activities/heart/date/today/1d.json');
  debugPrint(response.data);
}
