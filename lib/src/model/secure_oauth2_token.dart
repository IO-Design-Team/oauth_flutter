import 'package:fresh_dio/fresh_dio.dart';
import 'package:json_annotation/json_annotation.dart';
import 'package:jwt_decoder/jwt_decoder.dart';

part 'secure_oauth2_token.g.dart';

/// An OAuth token response
///
/// Includes extra information common in secure OAuth transactions:
/// - [idToken] - The id token
/// - [rawNonce] - The unencoded nonce
/// - [nonce] - The encoded nonce
/// - [state] - The state
@JsonSerializable()
class SecureOAuth2Token implements OAuth2Token {
  /// The access token
  @override
  @JsonKey(name: 'access_token')
  final String accessToken;

  /// The token type
  @override
  @JsonKey(name: 'token_type')
  final String? tokenType;

  /// The expiry time
  @override
  @JsonKey(name: 'expires_in')
  final int? expiresIn;

  /// The refresh token if available
  @override
  @JsonKey(name: 'refresh_token')
  final String? refreshToken;

  /// The id token
  @JsonKey(name: 'id_token')
  final String? idToken;

  @override
  final String? scope;

  /// The state
  final String? state;

  /// The unencoded nonce
  /// 
  /// This is used by services such as Firebase for implicit OIDC
  final String rawNonce;

  /// The encoded nonce
  @JsonKey(includeToJson: false, includeFromJson: false)
  late final String? nonce;

  /// Constructor
  SecureOAuth2Token({
    required this.accessToken,
    this.tokenType,
    this.expiresIn,
    this.refreshToken,
    this.scope,
    this.idToken,
    this.state,
    required this.rawNonce,
  }) {
    final idToken = this.idToken;

    if (idToken == null) {
      nonce = null;
      return;
    }

    final jwt = JwtDecoder.decode(idToken);
    nonce = jwt['nonce'];
  }

  /// From json
  factory SecureOAuth2Token.fromJson(Map<String, dynamic> json) =>
      _$SecureOAuth2TokenFromJson(json);

  /// To json
  Map<String, dynamic> toJson() => _$SecureOAuth2TokenToJson(this);
}
