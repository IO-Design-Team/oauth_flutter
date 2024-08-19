// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'oauth2_endpoints.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

OAuth2Endpoints _$OAuth2EndpointsFromJson(Map<String, dynamic> json) =>
    OAuth2Endpoints(
      authorization: json['authorization_endpoint'] as String,
      token: json['token_endpoint'] as String,
      revocation: json['revocation_endpoint'] as String?,
    );

Map<String, dynamic> _$OAuth2EndpointsToJson(OAuth2Endpoints instance) =>
    <String, dynamic>{
      'authorization_endpoint': instance.authorization.toString(),
      'token_endpoint': instance.token.toString(),
      'revocation_endpoint': instance.revocation?.toString(),
    };
