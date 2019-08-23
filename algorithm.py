# coding=utf-8
import binascii
from copy import copy
from memory_profiler import memory_usage

from tables import Tables


class GOST3412_2015:
    tables = None

    def __init__(self):
        self.tables = Tables()

    def start_encrypt(self, message, start_key):
        round_key = [start_key[:16], start_key[16:]]
        round_keys = round_key + self.generate_key(round_key)
        return self.encrypt(message, round_keys)

    def start_decrypt(self, cipher, start_key):
        round_key = [start_key[:16], start_key[16:]]
        round_keys = round_key + self.generate_key(round_key)
        return self.decrypt(cipher, round_keys)

    def generate_key(self, round_key):
        round_keys = []
        for i in range(4):
            for k in range(8):
                round_key = self.feistel(self.tables.c[8 * i + k], round_key)
            round_keys.append(round_key[0])
            round_keys.append(round_key[1])
        return round_keys

    def feistel(self, c, k):
        tmp = self.x_box(c, k[0])
        tmp = self.s_box(tmp)
        tmp = self.L_box(tmp)
        tmp = self.x_box(tmp, k[1])
        return [tmp, k[0]]

    # x_box: k = k xor a
    def x_box(self, k, a):
        tmp = copy(k)
        for i in range(0, len(k)):
            tmp[i] ^= a[i]
        return tmp

    def s_box(self, a):
        res = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for i in range(len(a)):
            res[i] = self.tables.pi[a[i]]
        return res

    def s_box_inv(self, a):
        res = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for i in range(len(a)):
            res[i] = self.tables.pi_inv[a[i]]
        return res

    def L_box(self, a):
        for i in range(len(a)):
            a = self.R_box(a)
        return a

    def L_box_inv(self, a):
        for i in range(len(a)):
            a = self.R_box_inv(a)
        return a

    def R_box(self, a):
        return [self.l_box(a)] + a[:-1]

    def R_box_inv(self, a):
        return a[1:] + [self.l_box(a[1:] + [a[0]])]

    # l_box: l(a15..a0) = 148 * a15 + 32 * a14 ... + 1 * a0
    def l_box(self, a):
        coef = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]
        mul_coef = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for i in range(0, len(coef)):
            mul_coef[i] = self.tables.mul_table[a[i]][coef[i]]
        res = 0
        for i in mul_coef:
            res ^= i
        return res

    def encrypt(self, message, round_keys):
        tmp = message
        for i in range(9):
            tmp = self.x_box(tmp, round_keys[i])
            tmp = self.s_box(tmp)
            tmp = self.L_box(tmp)
        tmp = self.x_box(tmp, round_keys[9])

        return tmp

    def decrypt(self, cipher, round_keys):
        tmp = cipher
        for i in range(9, 0, -1):
            tmp = self.x_box(tmp, round_keys[i])
            tmp = self.L_box_inv(tmp)
            tmp = self.s_box_inv(tmp)
        tmp = self.x_box(tmp, round_keys[0])
        return tmp


def start():
    algo = GOST3412_2015()
    mtest = list(binascii.unhexlify('123456789123456789abcdefabcdef12'))
    ktest = list(binascii.unhexlify('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef'))
    print(ktest)
    ctest = algo.start_encrypt(mtest, ktest)
    print (binascii.hexlify(bytearray(ctest)))

    m = algo.start_decrypt(ctest, ktest)
    print (binascii.hexlify(bytearray(m)))
    print(memory_usage())
start()