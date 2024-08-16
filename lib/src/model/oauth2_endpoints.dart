/// Wrapper for all OAuth2 endpoints
class OAuth2Endpoints {
  /// URI for authorization
  final Uri authorize;

  /// URI for token exchange
  final Uri token;

  /// URI for token revocation
  final Uri revoke;

  /// Construct with explicit URLs
  OAuth2Endpoints({
    required String authorize,
    required String token,
    required String revoke,
  })  : authorize = Uri.parse(authorize),
        token = Uri.parse(token),
        revoke = Uri.parse(revoke);

  /// Construct with a base URL
  ///
  /// Convenient for services that have a consistent base URL
  OAuth2Endpoints.base(String base)
      : this(
          authorize: '$base/authorize',
          token: '$base/token',
          revoke: '$base/revoke',
        );
}
