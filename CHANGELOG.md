## 0.0.13

- Upgrades `flutter_secure_storage` to `^11.0.0`

## 0.0.12

- Upgrades `fresh_dio` to `0.6.0`
- Injects the `issuedAt` timestamp into the token decoder

## 0.0.11+1

- Adds PR credit

## 0.0.11

- Actually awaits the refresh method so reauthentication can happen (by [@bocsir](https://github.com/bocsir) in [#7](https://github.com/IO-Design-Team/oauth_flutter/pull/7))

## 0.0.10

- Dependency upgrades

## 0.0.9

- Only validates a refresh token nonce if it exists

## 0.0.8

- Makes `OAuth2ClientCredentials.secret` optional (by [@mike-500](https://github.com/mike-500) in [#5](https://github.com/IO-Design-Team/oauth_flutter/pull/5))

## 0.0.7

- Adds support for `end_session_endpoint`
- Improves the utility of `OAuth2Endpoints.base`

## 0.0.6

- Specifies a generic type on the `Fresh` field

## 0.0.5

- Fixes token refresh serialization issue

## 0.0.4

- Adds `interceptCallback` parameter to allow for custom interception of the callback URL
- Adds `isAuthenticated` method to check if the user is authenticated

## 0.0.3

- Supports discovery

## 0.0.2

- Adds token revocation support

## 0.0.1

- Initial release
