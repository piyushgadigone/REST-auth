import datetime
import pyotp
import base64
import hashlib
import hmac
import six
import struct
import time

class GoogleTotpAuth:
    @staticmethod
    def generate_secret():
        return pyotp.random_base32()
    
    @staticmethod
    def _is_possible_token(token):
	if not isinstance(token, bytes):
            token = six.b(str(token))
        return token.isdigit() and len(token) <= 6

    @staticmethod
    def get_hotp(secret, intervals_no, as_string=False, casefold=True):
        if isinstance(secret, six.string_types):
            # It is unicode, convert it to bytes
            secret = secret.encode('utf-8')
        try:
            key = base64.b32decode(secret, casefold=casefold)
        except (TypeError):
            raise TypeError('Incorrect secret')
        msg = struct.pack('>Q', intervals_no)
        hmac_digest = hmac.new(key, msg, hashlib.sha1).digest()
        ob = hmac_digest[19] if six.PY3 else ord(hmac_digest[19])
        o = ob & 15
        token_base = struct.unpack('>I', hmac_digest[o:o + 4])[0] & 0x7fffffff
        token = token_base % 1000000
        if as_string:
            # TODO: should as_string=True return unicode, not bytes?
            return six.b('{:06d}'.format(token))
        else:
            return token

    @staticmethod
    def get_totp(secret, as_string=False):
        interv_no = int(time.time()) // 30
        return GoogleTotpAuth.get_hotp(secret, intervals_no=interv_no, as_string=as_string)

    @staticmethod
    def generate_token(self):
        return GoogleTotpAuth.get_totp(self.secret)

    @staticmethod
    def valid_hotp(token, secret, last=1, trials=1000):
        if not GoogleTotpAuth._is_possible_token(token):
            return False
        for i in six.moves.xrange(last + 1, last + trials + 1):
            if GoogleTotpAuth.get_hotp(secret=secret, intervals_no=i) == int(token):
                return i
        return False

    @staticmethod
    def valid_totp(token, secret):
        #return GoogleTotpAuth._is_possible_token(token)
        return GoogleTotpAuth._is_possible_token(token) and int(token) == GoogleTotpAuth.get_totp(secret)
