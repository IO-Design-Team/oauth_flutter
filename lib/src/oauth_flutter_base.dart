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
typedef ReAuthenticationCallback<T extends SecureOAuth2Token> = Future<T?>
    Function();

/// Decoder for the OAuth2 token
///
/// This can be overridden to decode custom tokens
typedef OAuth2TokenDecoder<T extends SecureOAuth2Token> = T Function(
  Map<String, dynamic> json,
);

/// A client that handles the complete OAuth2 flow
///
/// Handles token generation, storage, and refreshing
class OAuth2Client<T extends SecureOAuth2Token> {
  static const _uuid = Uuid();
  static const _keyPrefix = '_oauth_flutter_token_';

  /// Access to the OAuth dio client
  ///
  /// Must include the base path for API operations. This is the OAuth audience.
  final Dio dio;

  /// The client to use for OAuth operations
  final Dio oauthDio;

  /// The OAuth2 endpoints
  final OAuth2Endpoints endpoints;

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
  ///
  /// If using a custom token type, you MUST pass a custom [tokenDecoder]
  final OAuth2TokenDecoder<T> tokenDecoder;

  /// **Only has an effect on Web!**
  /// Can be used to override the origin of the redirect URL.
  /// This is useful for cases where the redirect URL is not on the same
  /// domain (e.g. local testing).
  final String? redirectOriginOverride;

  /// Verification configuration
  ///
  /// Not all services support all verification options
  final OAuth2Verification verification;

  /// The token refresher
  late final Fresh fresh;

  /// Constructor
  OAuth2Client({
    required String key,
    required this.dio,
    Dio? oauthDio,
    required this.endpoints,
    required this.redirectUri,
    this.callbackUrlScheme = 'https',
    this.credentials,
    this.scope = const {},
    OAuth2TokenDecoder<T>? tokenDecoder,
    ReAuthenticationCallback<T>? onReAuthenticate,
    this.redirectOriginOverride,
    this.verification = const OAuth2Verification(),
  })  : tokenDecoder =
            tokenDecoder ?? SecureOAuth2Token.fromJson as OAuth2TokenDecoder<T>,
        oauthDio = oauthDio ?? Dio() {
    fresh = Fresh.oAuth2(
      tokenStorage: SecureTokenStorage(
        key: '$_keyPrefix$key',
        decoder: this.tokenDecoder,
      ),
      refreshToken: (token, dio) => _refreshToken(
        oldToken: token as T?,
        onReAuthenticate: onReAuthenticate ?? authenticate,
      ),
    );
    dio.interceptors.add(fresh);
  }

  Future<T> _refreshToken({
    required T? oldToken,
    required ReAuthenticationCallback<T> onReAuthenticate,
  }) async {
    Future<T> reauthenticate() async {
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
    final uri = endpoints.authorize.replace(
      path: endpoints.authorize.path,
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
      options: FlutterWebAuth2Options(
        debugOrigin: redirectOriginOverride,
        httpsHost: redirectUri.host,
        httpsPath: redirectUri.path,
      ),
    );

    return OAuthAuthorization.fromUrl(
      url: result,
      codeVerifier: pkce.codeVerifier,
      state: state,
      rawNonce: rawNonce,
    );
  }

  /// Perform the OAuth2 token exchange
  Future<T> token({
    required OAuthAuthorization authorization,
  }) async {
    final credentials = this.credentials;
    final response = await oauthDio.postUri(
      endpoints.token,
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
    if (verification.tokenState && token.state != authorization.state) {
      throw Exception('State mismatch');
    }
    if (verification.tokenNonce && token.rawNonce.sha256 != token.nonce) {
      throw Exception('Nonce mismatch');
    }

    return token;
  }

  /// Refresh the OAuth2 token
  Future<T> refresh({
    required T token,
  }) async {
    final response = await oauthDio.postUri(
      endpoints.token,
      options: Options(headers: _tokenHeaders),
      data: {
        'grant_type': 'refresh_token',
        'refresh_token': token.refreshToken,
        'scope': token.scope,
      },
    );

    final newToken = tokenDecoder(response.data);
    if (verification.tokenNonce && newToken.nonce != token.nonce) {
      throw Exception('Nonce mismatch');
    }

    return newToken;
  }

  /// Revoke the OAuth2 token
  Future<void> revoke() async {
    final token = await fresh.token as T?;
    if (token == null) return;

    final credentials = this.credentials;
    final response = await oauthDio.postUri(
      endpoints.revoke,
      options: Options(headers: _tokenHeaders),
      data: {
        if (credentials != null) 'client_id': credentials.id,
        'token': token.accessToken,
      },
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to revoke token');
    }

    await fresh.clearToken();
  }

  /// Perform the entire OAuth2 flow
  Future<T> authenticate() async {
    final authorization = await authorize();
    final token = await this.token(authorization: authorization);
    await fresh.setToken(token);
    return token;
  }
}

extension on String {
  String get sha256 => crypto.sha256.convert(utf8.encode(this)).toString();
}
