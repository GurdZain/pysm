# coding=utf-8
# This is a **32bit** python program
#自动加密脚本
import SM2Python as sm2
#automatic encryption script
import binascii

def auto_encrypt(plain: str, pubkey: str, str_random: str, raw = False):
    '''
    输入 明文字符串,私钥，随机字符串
    提供raw=True则默认输入为原生字符串,否则必须为十六进制字符串格式
    返回两个值，第一个为公钥，第二个为十六进制格式的加密字符串。
    '''
    if raw:
        prikey = binascii.hexlify(plain)
        str_random = binascii.hexlify(str_random)
        plain = binascii.hexlify(plain)
    try:
        assert(len(pubkey) == 64 and len(str_random) == 64)
    except AssertionError:
        print("Fail to meet the demands")
    #pubkey = sm2.SM2GenKey(prikey)
    incre = 62
    #字符串分组，组长为62*4=248bit，不够的加0
    block = [plain[i:i + incre] for i in range(0,len(plain),incre)]
    if len(block[-1])<incre:
        block[-1] += '0'*(incre - len(block[-1]))
    cipher = [];
    for each in block:
        cipher.append(sm2.SM2Encrypt(str_random, pubkey, each))
    cipher = ''.join(cipher)
    return cipher

def auto_decrypt(cipher: str, prikey: str, length = None):
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
    while plain[-1] == '0':
        if length != None and len(plain)>length:
            plain.pop()
        elif length != None and len(plain)<=length:
            break
        else:
            plain.pop()
    plain = ''.join(plain)
    return plain

if __name__ == '__main__':
    #测试是否可用
    str_random = "F6000277CA814FFF1D7BA2E499297B0E00F8575DCF5F3480C00FCB7DFFBA743E"
    prikey = "50E7324D208DC091C089FB98FAEC64468EAE6789B0F707EDFE86EF7CB754DAEA"
    plain =  "B0448E89946BB21EC649FDF3BA46296602182849FBE2D329AAF843DE0D7CA7ABCDEF"
    pubkey = sm2.SM2GenKey(prikey)
    cipher = auto_encrypt(plain, pubkey, str_random)
    decoded = auto_decrypt(cipher, prikey)
    print(plain)
    print(decoded)
