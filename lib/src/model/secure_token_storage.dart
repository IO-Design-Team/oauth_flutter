import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:fresh_dio/fresh_dio.dart';
import 'package:oauth_flutter/src/model/secure_oauth2_token.dart';

/// A [TokenStorage] implementation backed by [FlutterSecureStorage]
class SecureTokenStorage extends TokenStorage<SecureOAuth2Token> {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  /// The key for storing the token
  final String key;

  /// Constructor
  SecureTokenStorage({required this.key});

  @override
  Future<void> delete() => _storage.delete(key: key);

  @override
  Future<SecureOAuth2Token?> read() async {
    final json = await _storage.read(key: key);
    if (json == null) return null;
    return SecureOAuth2Token.fromJson(jsonDecode(json));
  }

  @override
  Future<void> write(SecureOAuth2Token token) =>
      _storage.write(key: key, value: jsonEncode(token));
}
