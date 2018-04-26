import SM2Python as sm2
import hashlib
import binascii
import pysm4 as sm4
import base64


def sm4_encrypt(s: str, key: str):
    return sm4.encrypt_ecb(s,key)


def sm4_decrypt(s: str,key: str):
    return sm4.decrypt_ecb(s,key)


def sm2_encrypt(plain: str, pubkey: str, str_random: str, raw = False):
    '''
    输入 明文字符串,私钥，随机字符串
    提供raw=True则默认输入为原生字符串,否则必须为十六进制字符串格式。
    注意：pubkey为prikey生成，必须为十六进制格式字符串。
    返回两个值，第一个为公钥，第二个为十六进制格式的加密字符串。
    '''
    if raw:
        str_random = binascii.hexlify(str_random)
        plain = binascii.hexlify(plain.encode()).decode()
    try:
        assert(len(pubkey) == 128 and len(str_random) == 64)
    except AssertionError:
        print("Fail to meet the demands")
    if(isinstance(plain, bytes)):
        plain = plain.decode()
    incre = 62
    #字符串分组，组长为62hex*4=248bit，不够的加0
    block = [plain[i:i + incre] for i in range(0,len(plain),incre)]
    if len(block[-1])<incre:
        block[-1] += '0'*(incre - len(block[-1]))
    cipher = [];
    for each in block:
        cipher.append(sm2.SM2Encrypt(str_random, pubkey, each))
    cipher = ''.join(cipher)
    return cipher


def sm2_decrypt(cipher: str, prikey: str, length = None):
    '''
    返回十六进制明文字符串,length指明文是否有固定的长度
    '''
    incre = 254
    # 密文快为254*4bit
    block = [cipher[i:i + incre] for i in range(0,len(cipher),incre)]
    plain = []
    for each in block:
        plain.append(sm2.SM2Decrypt(each, prikey))
    plain = ''.join(plain)
    plain = list(plain)
    #print(plain)
    while plain[-1] == '0':
        if length != None and len(plain)>length:
            plain.pop()
        elif length != None and len(plain)<=length:
            break
        else:
            plain.pop()
    plain = ''.join(plain)
    return plain


def auto_encrypt(plain:str, sm4_key:str, sm2_key:str, random_str:str, salt: str,isPub = True, raw = True):
    '''
    传入参数：plain:明文， sm4_key：sm4密钥，sm2_key:sm2密钥，random_str:sm2随机字符串
    salt:密文组合的时候需要用到的盐,isPub如果为False,则传入的sm2密钥解释为私钥。
    raw=True表示传入SM2的字符串为原生字符串
    '''
    sm4cipher = sm4_encrypt(plain, sm4_key)
    sm4cipher = binascii.hexlify(base64.b64decode(sm4cipher)).decode('utf-8')#hexlize
    if raw == True:
        random_str = binascii.hexlify(random_str.encode())
    if isPub == False:
        sm2_key = binascii.hexlify(sm2_key.encode())
        sm2_key = sm2.SM2GenKey(sm2_key)
    if isinstance(random_str ,bytes):
        random_str = random_str.decode()
    sm2cipher = sm2_encrypt(binascii.hexlify(sm4_key.encode()).decode(),sm2_key,random_str)
    salted = sm4cipher + salt
    MD5 = hashlib.md5(salted.encode()).hexdigest()
    combined = sm4cipher + MD5 + sm2cipher
    return combined

def auto_decrypt(cipher:str, sm2_prikey:str, salt:str, raw = True):
    for i in range(1,len(cipher)):
        salted = cipher[0:i] + salt
        if hashlib.md5(salted.encode()).hexdigest() == cipher[i:i+32]:
            sm4cipher = cipher[0:i]
            sm2cipher = cipher[i+32:]
            break
    sm4_key = sm2_decrypt(sm2cipher, sm2_prikey)
    sm4_key = binascii.unhexlify(sm4_key).decode()
    sm4cipher = base64.b64encode(binascii.unhexlify(sm4cipher)).decode()
    plain = sm4_decrypt(sm4cipher, sm4_key)
    return plain

if __name__ == '__main__':
    '''
    Test section,输入最好按照我的格式
    '''
    plain = '\x60\xAE\x23\xEA'
    sm4_key = 'AVCDFFSkPksdyuss'#the length of sm4_key must be smaller than 128bit or 16Bytes
    prikey = 'abcd'*16#sm2_key must be 256bit string
    pubkey = sm2.SM2GenKey(prikey)
    random_str = "00F8575DCF5F3480C00FCB7DFFBA743E"#256bit string
    salt = 'salt'
    encoded = auto_encrypt(plain, sm4_key, pubkey, random_str, salt, isPub=True)
    print(encoded)
    decoded = auto_decrypt(encoded, prikey, salt)
    print(plain)
    print(decoded)
