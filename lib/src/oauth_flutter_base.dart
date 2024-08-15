import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:fresh_dio/fresh_dio.dart';
import 'package:oauth_flutter/oauth_flutter.dart';
import 'package:oauth_flutter/src/model/secure_token_storage.dart';
import 'package:pkce/pkce.dart';
import 'package:uuid/uuid.dart';
import 'package:crypto/crypto.dart' as crypto;

/// A request for re-authentication
///
/// Called when the refresh token has expired. An example use-case for not
/// returning a token is to prompt the user with the option to re-auth as a
/// Snackbar instead of forcing re-auth immediately.
typedef ReAuthenticationCallback = Future<SecureOAuth2Token?> Function();

/// Decoder for the OAuth2 token
///
/// This can be overridden to decode custom tokens
typedef OAuth2TokenDecoder = SecureOAuth2Token Function(
  Map<String, dynamic> json,
);

/// A client that handles the complete OAuth2 flow
///
/// Handles token generation, storage, and refreshing
class OAuth2Client {
  static const _uuid = Uuid();
  static const _keyPrefix = '_oauth_flutter_token_';

  /// Access to the OAuth dio client
  final Dio dio;

  /// The token refresher
  late final Fresh fresh;

  /// The base URI for OAuth2 operations
  final Uri oauthUri;

  /// The redirect URI
  final Uri redirectUri;

  /// The callback url scheme for native platforms
  ///
  /// This should kept as `https` for maximum security. This requires the following setup:
  /// - [Universal Links](https://developer.apple.com/ios/universal-links/)
  /// - [App Links](https://developer.android.com/training/app-links/#android-app-links)
  final String callbackUrlScheme;

  /// The OAuth scope to request
  final Set<String> scope;

  /// The client credentials
  ///
  /// Optional in cases where they are injected server-side
  final OAuth2ClientCredentials? credentials;

  /// A function that decodes the token
  final OAuth2TokenDecoder tokenDecoder;

  /// **Only has an effect on Web!**
  /// Can be used to override the origin of the redirect URL.
  /// This is useful for cases where the redirect URL is not on the same
  /// domain (e.g. local testing).
  final String? redirectOriginOverride;

  /// Constructor
  OAuth2Client({
    required String key,
    required this.oauthUri,
    required this.redirectUri,
    this.callbackUrlScheme = 'https',
    this.credentials,
    this.scope = const {},
    this.tokenDecoder = SecureOAuth2Token.fromJson,
    BaseOptions? dioOptions,
    ReAuthenticationCallback? onReAuthenticate,
    this.redirectOriginOverride,
  }) : dio = Dio(dioOptions) {
    fresh = Fresh.oAuth2(
      tokenStorage: SecureTokenStorage(key: '$_keyPrefix$key'),
      refreshToken: (token, dio) => _refreshToken(
        oldToken: token as SecureOAuth2Token?,
        onReAuthenticate: onReAuthenticate ?? authenticate,
      ),
    );
    dio.interceptors.add(fresh);
  }

  Future<SecureOAuth2Token> _refreshToken({
    required SecureOAuth2Token? oldToken,
    required ReAuthenticationCallback onReAuthenticate,
  }) async {
    Future<SecureOAuth2Token> reauthenticate() async {
      final token = await onReAuthenticate();
      if (token == null) throw Exception('Re-authenticate returned no token');
      return token;
    }

    if (oldToken == null) return reauthenticate();

    try {
      return refresh(token: oldToken);
    } on DioException catch (e) {
      final statusCode = e.response?.statusCode;
      if (statusCode == null) rethrow;
      if (statusCode >= 400 && statusCode < 500) return reauthenticate();
      rethrow;
    }
  }

  Map<String, String> get _tokenHeaders {
    final credentials = this.credentials;
    return {
      'Content-Type': 'application/x-www-form-urlencoded',
      if (credentials != null)
        'Authorization':
            'Basic ${base64Encode(utf8.encode('${credentials.id}:${credentials.secret}'))}',
    };
  }

  /// Perform the OAuth2 authorization flow
  Future<OAuthAuthorization> authorize() async {
    final rawNonce = _uuid.v4();
    final state = _uuid.v4();
    final pkce = PkcePair.generate();

    final credentials = this.credentials;
    final uri = oauthUri.replace(
      path: '${oauthUri.path}/authorize',
      queryParameters: {
        if (credentials != null) 'client_id': credentials.id,
        'response_type': 'code',
        'redirect_uri': redirectUri.toString(),
        'scope': scope.join(' '),
        'aud': dio.options.baseUrl,
        'nonce': rawNonce.sha256,
        'state': state,
        'code_challenge': pkce.codeChallenge,
        'code_challenge_method': 'S256',
      },
    );

    final result = await FlutterWebAuth2.authenticate(
      url: uri.toString(),
      callbackUrlScheme: callbackUrlScheme,
      options: FlutterWebAuth2Options(debugOrigin: redirectOriginOverride),
    );

    return OAuthAuthorization.fromUrl(
      url: result,
      codeVerifier: pkce.codeVerifier,
      state: state,
      rawNonce: rawNonce,
    );
  }

  /// Perform the OAuth2 token exchange
  Future<SecureOAuth2Token> token({
    required OAuthAuthorization authorization,
  }) async {
    final credentials = this.credentials;
    // Use a fresh Dio instance to bypass [Fresh]
    final response = await Dio().postUri(
      oauthUri.replace(path: '${oauthUri.path}/token'),
      options: Options(headers: _tokenHeaders),
      data: {
        if (credentials != null) 'client_id': credentials.id,
        'grant_type': 'authorization_code',
        'redirect_uri': redirectUri.toString(),
        'code': authorization.code,
        'code_verifier': authorization.codeVerifier,
      },
    );

    final token = tokenDecoder({
      ...response.data,
      // Store the raw nonce for easier OIDC compatibility
      'rawNonce': authorization.rawNonce,
    });
    if (token.state != authorization.state) {
      throw Exception('State mismatch');
    }
    if (token.rawNonce.sha256 != token.nonce) {
      throw Exception('Nonce mismatch');
    }

    return token;
  }

  /// Refresh the OAuth2 token
  Future<SecureOAuth2Token> refresh({
    required SecureOAuth2Token token,
  }) async {
    // Use a fresh Dio instance to bypass [Fresh]
    final response = await Dio().postUri(
      oauthUri.replace(path: '${oauthUri.path}/token'),
      options: Options(headers: _tokenHeaders),
      data: {
        'grant_type': 'refresh_token',
        'refresh_token': token.refreshToken,
        'scope': token.scope,
      },
    );

    final newToken = tokenDecoder(response.data);
    if (newToken.nonce != token.nonce) {
      throw Exception('Nonce mismatch');
    }

    return newToken;
  }

  /// Perform the entire OAuth2 flow
  Future<SecureOAuth2Token> authenticate() async {
    final authorization = await authorize();
    final token = await this.token(authorization: authorization);
    await fresh.setToken(token);
    return token;
  }
}

extension on String {
  String get sha256 => crypto.sha256.convert(utf8.encode(this)).toString();
}
