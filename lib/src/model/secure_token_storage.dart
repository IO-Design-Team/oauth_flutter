import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:fresh_dio/fresh_dio.dart';
import 'package:oauth_flutter/oauth_flutter.dart';

/// A [TokenStorage] implementation backed by [FlutterSecureStorage]
class SecureTokenStorage<T extends SecureOAuth2Token> extends TokenStorage<T> {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  /// The key for storing the token
  final String key;

  /// The token decoder
  final OAuth2TokenDecoder<T> decoder;

  /// Constructor
  SecureTokenStorage({required this.key, required this.decoder});

  @override
  Future<void> delete() => _storage.delete(key: key);

  @override
  Future<T?> read() async {
    final json = await _storage.read(key: key);
    if (json == null) return null;
    return decoder(jsonDecode(json));
  }

  @override
  Future<void> write(T token) =>
      _storage.write(key: key, value: jsonEncode(token));
}
