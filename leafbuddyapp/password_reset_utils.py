from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.conf import settings

signer = TimestampSigner()

def generate_password_reset_token(email):
    return signer.sign(email)

def verify_password_reset_token(token, max_age=3600):  # 1 hour default
    try:
        email = signer.unsign(token, max_age=max_age)
        return email
    except SignatureExpired:
        return None
    except BadSignature:
        return None
