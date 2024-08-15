// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'secure_oauth2_token.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

SecureOAuth2Token _$SecureOAuth2TokenFromJson(Map<String, dynamic> json) =>
    SecureOAuth2Token(
      accessToken: json['access_token'] as String,
      tokenType: json['token_type'] as String?,
      expiresIn: (json['expires_in'] as num?)?.toInt(),
      refreshToken: json['refresh_token'] as String?,
      scope: json['scope'] as String?,
      idToken: json['id_token'] as String?,
      state: json['state'] as String?,
      rawNonce: json['rawNonce'] as String,
    );

Map<String, dynamic> _$SecureOAuth2TokenToJson(SecureOAuth2Token instance) =>
    <String, dynamic>{
      'access_token': instance.accessToken,
      'token_type': instance.tokenType,
      'expires_in': instance.expiresIn,
      'refresh_token': instance.refreshToken,
      'id_token': instance.idToken,
      'scope': instance.scope,
      'state': instance.state,
      'rawNonce': instance.rawNonce,
    };
