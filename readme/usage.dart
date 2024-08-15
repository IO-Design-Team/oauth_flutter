import 'package:oauth_flutter/oauth_flutter.dart';

final oauthUri = Uri.parse('https://www.fitbit.com/oauth2');

void main() async {
  final client = OAuth2Client(
    key: 'fitbit',
    authorizationUri: authorizationUri,
    tokenUri: tokenUri,
    redirectUri: redirectUri,
    credentials: credentials,
  );
}
