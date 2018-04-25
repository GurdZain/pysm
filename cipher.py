import sm2
import hashlib
import binascii
import struct
import pysm4 as sm4
from SM3 import sm3hash as hash

def b(s):
    return bytes(s.encode())

def long_to_bytes(n, blocksize=0):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.

    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = b('')
    n = int(n)
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffff) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != b('\000')[0]:
            break
    else:
        # only happens when n == 0
        s = b('\000')
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b('\000') + s
    return s

def bytes_to_long(s):
    """bytes_to_long(string) : long
    Convert a byte string to a long integer.

    This is (essentially) the inverse of long_to_bytes().
    """
    acc = 0
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b('\000') * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc

def sm4_encrypt(s, key):
    if(not isinstance(s, int)):
        s = bytes_to_long(b(s))
    if(not isinstance(key, int)):
        key = bytes_to_long(b(key))
    return sm4.encrypt(s,key)

def sm4_decrypt(s,key):
    if(not isinstance(s, int)):
        s = bytes_to_long(b(s))
    if(not isinstance(key, int)):
        key = bytes_to_long(b(key))
    return long_to_bytes(sm4.decrypt(s,key)).decode('utf-8')

def sm2_encrypt(plain, prikey, str_random, raw = False):
    return sm2.auto_encrypt(plain, prikey, str_random, raw)

def sm2_decrypt(cipher, prikey, length = None):
    return sm2.auto_decrypt(cipher,prikey,length)


def encrypt(plain, sm4_key, sm2_key, random_str, salt: str,isPub = True, raw = True):
    '''
    传入参数：plain:明文， sm4_key：sm4密钥，sm2_key:sm2密钥，random_str:sm2随机字符串
    salt:密文组合的时候需要用到的盐,isPub如果为False,则传入的sm2密钥解释为私钥。
    raw=True表示传入SM2的字符串为原生字符串
    '''
    sm4cipher = sm4_encrypt(bytes_to_long(plain.encode()),bytes_to_long(sm4_key.encode()))
    sm4cipher = binascii.hexlify(long_to_bytes(sm4cipher).decode('utf-8'))
    if raw == True:
        sm2_key = binascii.hexlify(sm2_key)
        random_str = binascii.hexlify(random_str)
    if isPub == False:
        sm2_key = sm2.SM2GenKey(sm2_key)
    sm2cipher = sm2_encrypt(binascii.hexlify(sm4_key),sm2_key,str_random)
    salted = sm4_cipher + salt
    MD5 = hashlib.md5(salted.encode()).hexdigest()
    combined = sm4cipher + MD5 + sm2cipher
    return combined

def decrypt(cipher, sm2_prikey, salt, raw = True):
    for i in range(1,len(cipher)):
        salted = cipher[0:i] + salt
        if hashlib.md5(salted).hexdigest() == cipher[i:i+32]:
            sm4cipher = cipher[0:i]
            sm2cipher = cipher[i+32:]
            break
    sm4_key = sm2_decrypt(sm2cipher, sm2_prikey)
    sm4_key = binascii.unhexlify(sm4_key)
    plain = sm4_decrypt(cipher, sm4_key)
    return plain

if __name__ == '__main__':
    x = '前列腺炎'
    key = '1231324'
    l = bytes_to_long(x.encode())
    print(l)
    ci = sm4_encrypt(l,key)
    print(ci)
    de = sm4_decrypt(ci,key)
    print(hash(key))
