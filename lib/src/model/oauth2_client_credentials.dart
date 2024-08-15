/// A wrapper for OAuth2 client credentials
class OAuth2ClientCredentials {
  /// The client ID
  final String id;

  /// The client secret
  final String secret;

  /// Constructor
  const OAuth2ClientCredentials({required this.id, required this.secret});
}
