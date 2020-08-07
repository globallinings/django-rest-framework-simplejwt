.. _settings:

Settings
========

Some of Simple JWT's behavior can be customized through settings variables in
``settings.py``:

.. code-block:: python

  # Django project settings.py

  from datetime import timedelta

  ...

  SIMPLE_JWT = {
      'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
      'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
      'ROTATE_REFRESH_TOKENS': False,
      'BLACKLIST_AFTER_ROTATION': True,

      'ALGORITHM': 'HS256',
      'SIGNING_KEY': settings.SECRET_KEY,
      'VERIFYING_KEY': None,
      'AUDIENCE': None,
      'ISSUER': None,

      'AUTH_HEADER_TYPES': ('Bearer',),
      'USER_ID_FIELD': 'id',
      'USER_ID_CLAIM': 'user_id',

      'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
      'TOKEN_TYPE_CLAIM': 'token_type',

      'JTI_CLAIM': 'jti',

      'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
      'SLIDING_TOKEN_LIFETIME': timedelta(minutes=5),
      'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),

      'DYNAMIC_AUDIENCE_HEADER_FIELD': 'HTTP_ORIGIN',
      'ALLOW_NO_AUDIENCE': False,
  }

Above, the default values for these settings are shown.

``ACCESS_TOKEN_LIFETIME``
-------------------------

A ``datetime.timedelta`` object which specifies how long access tokens are
valid.  This ``timedelta`` value is added to the current UTC time during token
generation to obtain the token's default "exp" claim value.

``REFRESH_TOKEN_LIFETIME``
--------------------------

A ``datetime.timedelta`` object which specifies how long refresh tokens are
valid.  This ``timedelta`` value is added to the current UTC time during token
generation to obtain the token's default "exp" claim value.

``ROTATE_REFRESH_TOKENS``
-------------------------

When set to ``True``, if a refresh token is submitted to the
``TokenRefreshView``, a new refresh token will be returned along with the new
access token.  This new refresh token will be supplied via a "refresh" key in
the JSON response.  New refresh tokens will have a renewed expiration time
which is determined by adding the timedelta in the ``REFRESH_TOKEN_LIFETIME``
setting to the current time when the request is made.  If the blacklist app is
in use and the ``BLACKLIST_AFTER_ROTATION`` setting is set to ``True``, refresh
tokens submitted to the refresh view will be added to the blacklist.

``BLACKLIST_AFTER_ROTATION``
----------------------------

When set to ``True``, causes refresh tokens submitted to the
``TokenRefreshView`` to be added to the blacklist if the blacklist app is in
use and the ``ROTATE_REFRESH_TOKENS`` setting is set to ``True``.

``ALGORITHM``
-------------

The algorithm from the PyJWT library which will be used to perform
signing/verification operations on tokens.  To use symmetric HMAC signing and
verification, the following algorithms may be used: ``'HS256'``, ``'HS384'``,
``'HS512'``.  When an HMAC algorithm is chosen, the ``SIGNING_KEY`` setting
will be used as both the signing key and the verifying key.  In that case, the
``VERIFYING_KEY`` setting will be ignored.  To use asymmetric RSA signing and
verification, the following algorithms may be used: ``'RS256'``, ``'RS384'``,
``'RS512'``.  When an RSA algorithm is chosen, the ``SIGNING_KEY`` setting must
be set to a string that contains an RSA private key.  Likewise, the
``VERIFYING_KEY`` setting must be set to a string that contains an RSA public
key.

``SIGNING_KEY``
---------------

The signing key that is used to sign the content of generated tokens.  For HMAC
signing, this should be a random string with at least as many bits of data as
is required by the signing protocol.  For RSA signing, this should be a string
that contains an RSA private key that is 2048 bits or longer.  Since Simple JWT
defaults to using 256-bit HMAC signing, the ``SIGNING_KEY`` setting defaults to
the value of the ``SECRET_KEY`` setting for your django project.  Although this
is the most reasonable default that Simple JWT can provide, it is recommended
that developers change this setting to a value that is independent from the
django project secret key.  This will make changing the signing key used for
tokens easier in the event that it is compromised.

``VERIFYING_KEY``
-----------------

The verifying key which is used to verify the content of generated tokens.  If
an HMAC algorithm has been specified by the ``ALGORITHM`` setting, the
``VERIFYING_KEY`` setting will be ignored and the value of the ``SIGNING_KEY``
setting will be used.  If an RSA algorithm has been specified by the
``ALGORITHM`` setting, the ``VERIFYING_KEY`` setting must be set to a string
that contains an RSA public key.

``AUDIENCE``
-------------

The audience claim to be included in generated tokens and/or validated in
decoded tokens. When set to ``None``, this field is excluded from tokens and is
not validated.

If set to ``Dynamic``, the Dynamic Audience system is enabled and may be
further configured through ``DYNAMIC_AUDIENCE_HEADER_FIELD`` and
``ALLOW_NO_AUDIENCE`` to establish the content of the audience claim and
what should be verified against.


``ISSUER``
----------

The issuer claim to be included in generated tokens and/or validated in decoded
tokens. When set to ``None``, this field is excluded from tokens and is not
validated.

``AUTH_HEADER_TYPES``
---------------------

The authorization header type(s) that will be accepted for views that require
authentication.  For example, a value of ``'Bearer'`` means that views
requiring authentication would look for a header with the following format:
``Authorization: Bearer <token>``.  This setting may also contain a list or
tuple of possible header types (e.g. ``('Bearer', 'JWT')``).  If a list or
tuple is used in this way, and authentication fails, the first item in the
collection will be used to build the "WWW-Authenticate" header in the response.

``USER_ID_FIELD``
-----------------

The database field from the user model that will be included in generated
tokens to identify users.  It is recommended that the value of this setting
specifies a field that does not normally change once its initial value is
chosen.  For example, specifying a "username" or "email" field would be a poor
choice since an account's username or email might change depending on how
account management in a given service is designed.  This could allow a new
account to be created with an old username while an existing token is still
valid which uses that username as a user identifier.

``USER_ID_CLAIM``
-----------------

The claim in generated tokens which will be used to store user identifiers.
For example, a setting value of ``'user_id'`` would mean generated tokens
include a "user_id" claim that contains the user's identifier.

``AUTH_TOKEN_CLASSES``
----------------------

A list of dot paths to classes that specify the types of token that are allowed
to prove authentication.  More about this in the "Token types" section below.

``TOKEN_TYPE_CLAIM``
--------------------

The claim name that is used to store a token's type.  More about this in the
"Token types" section below.

``JTI_CLAIM``
-------------

The claim name that is used to store a token's unique identifier.  This
identifier is used to identify revoked tokens in the blacklist app.  It may be
necessary in some cases to use another claim besides the default "jti" claim to
store such a value.

``SLIDING_TOKEN_LIFETIME``
--------------------------

A ``datetime.timedelta`` object which specifies how long sliding tokens are
valid to prove authentication.  This ``timedelta`` value is added to the
current UTC time during token generation to obtain the token's default "exp"
claim value.  More about this in the "Sliding tokens" section below.

``SLIDING_TOKEN_REFRESH_LIFETIME``
----------------------------------

A ``datetime.timedelta`` object which specifies how long sliding tokens are
valid to be refreshed.  This ``timedelta`` value is added to the current UTC
time during token generation to obtain the token's default "exp" claim value.
More about this in the "Sliding tokens" section below.

``SLIDING_TOKEN_REFRESH_EXP_CLAIM``
-----------------------------------

The claim name that is used to store the expiration time of a sliding token's
refresh period.  More about this in the "Sliding tokens" section below.

``DYNAMIC_AUDIENCE_HEADER_FIELD``
---------------------------------

value to be passed to META.get() method on request object to retrieve the value
to be used in the AUD claim on creation of JWT and to obtain value for
comparison. Considering making this support a list of headers that can be
selected from as my read of the specification for JWT indicates AUD can be a
list of strings that any one matching from the client request to the AUD claim
provides a match.

The current implementation doesn't provide handling for multiple audience claim
strings to be configured however an endpoint can have a list of allowed
audience claims that the token provided audience claim will be checked against.

The default value ``HTTP_ORIGIN`` selects the Django mapping of the ``origin``
HTTP header automatically added by browsers when making an HTTP request and
the contents of this header is the FQDN string of the source domain without any
path information included (as opposed to the referrer header which contains url
path.

This header is not automatically added by clients such as postman (as these
do not have an FQDN for their origin however the origin header can be added
manually to allow testing against this system if ``Dynamic`` audience is
enabled.

``ALLOW_NO_AUDIENCE``
---------------------

A value of true allows a JWT with no audience claim to be accepted when
processing authentication of the supplied token. If set to False (default) (and
AUDIENCE is not None) then any token received missing AUD as a claim will be
immediately rejected as an invalid token (even if its signature would pass) and
if none of the DYNAMIC_AUDIENCE_HEADER_FIELD entries above provided a header
value then generating the token would fail (testing and failing on both to
ensure that any change in policy is effected before tokens expire and to
prevent a token generated with the same SIGNING_KEY being validated even if it
was allowed to be generated on another system). It is not advised to set this
to True except during a migration window where tokens generated beforehand
should be accepted or where only a new set of API endpoints are being added
that would require AUD claims and existing endpoints aren't being retrofitted.
The signature will still be checked and provided the SIGNING_KEY hasn't leaked
this should prevent people minting their own tokens even if the AUD is allowed
to pass.
