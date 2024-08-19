import 'package:json_annotation/json_annotation.dart';

part 'oauth2_endpoints.g.dart';

/// Wrapper for all OAuth2 endpoints
@JsonSerializable()
class OAuth2Endpoints {
  /// URI for authorization
  @JsonKey(name: 'authorization_endpoint')
  final Uri authorization;

  /// URI for token exchange
  @JsonKey(name: 'token_endpoint')
  final Uri token;

  /// URI for token revocation
  @JsonKey(name: 'revocation_endpoint')
  final Uri? revocation;

  /// Construct with explicit URLs
  OAuth2Endpoints({
    required String authorization,
    required String token,
    String? revocation,
  })  : authorization = Uri.parse(authorization),
        token = Uri.parse(token),
        revocation = revocation != null ? Uri.parse(revocation) : null;

  /// Construct with a base URL
  ///
  /// Convenient for services that have a consistent base URL
  OAuth2Endpoints.base(String base)
      : this(
          authorization: '$base/authorize',
          token: '$base/token',
          revocation: '$base/revoke',
        );

  /// From json
  factory OAuth2Endpoints.fromJson(Map<String, dynamic> json) =>
      _$OAuth2EndpointsFromJson(json);

  /// To json
  Map<String, dynamic> toJson() => _$OAuth2EndpointsToJson(this);
}
