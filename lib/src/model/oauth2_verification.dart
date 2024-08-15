/// Holds configuration for OAuth2 verification options
class OAuth2Verification {
  /// Verify the token state
  final bool tokenState;

  /// Verify the token nonce
  final bool tokenNonce;

  /// Constructor
  const OAuth2Verification({
    this.tokenState = true,
    this.tokenNonce = true,
  });
}
