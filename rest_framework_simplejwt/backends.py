import jwt
from django.utils.translation import gettext_lazy as _
from jwt import InvalidTokenError, MissingRequiredClaimError, InvalidAudienceError

from .exceptions import TokenBackendError
from .utils import format_lazy

ALLOWED_ALGORITHMS = (
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
)


class TokenBackend:
    def __init__(self, algorithm, signing_key=None, verifying_key=None, audience=None, issuer=None,
                 allow_no_audience=None):
        if algorithm not in ALLOWED_ALGORITHMS:
            raise TokenBackendError(format_lazy(_("Unrecognized algorithm type '{}'"), algorithm))

        self.algorithm = algorithm
        self.signing_key = signing_key
        self.audience = audience
        self.issuer = issuer
        self.allow_no_audience = allow_no_audience
        if algorithm.startswith('HS'):
            self.verifying_key = signing_key
        else:
            self.verifying_key = verifying_key

    def encode(self, payload):
        """
        Returns an encoded token for the given payload dictionary.
        """
        jwt_payload = payload.copy()
        if self.issuer is not None:
            jwt_payload['iss'] = self.issuer

        # Whether or not the dynamic audience system is enabled we remove the
        # dynamic_aud key from the payload to avoid putting confusing info
        # into the
        jwt_payload.pop('dynamic_aud', None)

        token = jwt.encode(jwt_payload, self.signing_key, algorithm=self.algorithm)
        return token.decode('utf-8')

    def decode(self, token, dynamic_aud=None, verify=True):
        """
        Performs a validation of the given token and returns its payload
        dictionary.

        Raises a `TokenBackendError` if the token is malformed, if its
        signature check fails, or if its 'exp' claim indicates it has expired.
        """
        if self.audience == "Dynamic":
            audience = dynamic_aud
        else:
            audience = self.audience

        print(audience)

        try:
            return jwt.decode(token, self.verifying_key, algorithms=[self.algorithm], verify=verify,
                              audience=audience, issuer=self.issuer,
                              options={'verify_aud': self.audience is not None})
        # MissingRequiredClaimError is used for *any* missing specified required claim
        # However it only triggers when audience is not None and no audience claim exists in the token
        # Therefore we retest the decode with an explicit non verification of audience claim to ensure
        # that the token otherwise still validates (audience check is currently last but explicit check)
        except (MissingRequiredClaimError, InvalidAudienceError):
            if self.allow_no_audience:
                # Consider throwing warning here to remind users they are running in an insecure mode
                # designed only for use during transitions to using or removing dynamic audience
                try:
                    return jwt.decode(token, self.verifying_key, algorithms=[self.algorithm], verify=verify,
                                      audience=None, issuer=self.issuer, options={'verify_aud': True})
                except InvalidTokenError:
                    raise TokenBackendError(_('Token is invalid or expired'))
            else:
                raise TokenBackendError(_('Token is invalid or expired'))
        except InvalidTokenError:
            raise TokenBackendError(_('Token is invalid or expired'))

    def validate_audience(self, token, acceptable_audience, verify=True):
        """
        Verifies if the token provided has an aud claim that matches an
        accepted audience value

        Raises a `TokenBackendError` if the token is malformed (shouldn't
        occur as this should have been caught during authentication, if its
        signature check fails (as above for malformed), or if its 'exp' claim
        indicates it has expired (this should only be a low risk as the time
        between checks should be very small), or if no list of acceptable
        audience is provided or if the tokens aud claim doesnt match any
        provided acceptable claims.

        This decode is similar to the original decode method however it is now
        separated specifically to validate audiences and ignores the allow no
        audience configuration setting as this is designed to be used by
        permission checkers with a requirement that aud is present as a claim
        and that it matches an allowed list of strings
        """
        if not isinstance(acceptable_audience, (str, list, tuple)):
            raise TokenBackendError(_('Invalid format for acceptable_audience'))

        try:
            return jwt.decode(token, self.verifying_key, algorithms=[self.algorithm], verify=verify,
                              audience=acceptable_audience, issuer=self.issuer,
                              options={'verify_aud': True})
        except InvalidTokenError:
            raise TokenBackendError(_('Token is invalid or expired'))
