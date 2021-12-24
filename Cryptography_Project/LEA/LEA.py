#-*- coding: utf-8 -*-
from .CipherMode import CipherMode

import platform
import struct

SIZE_128 = 16
SIZE_192 = 24
SIZE_256 = 32

block_size = 16


class LEA(object):
    # valid key sizes
    keySize = (SIZE_128,SIZE_192,SIZE_256)
    delta = [0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957]

    rk = None
    rounds = 0

    py_version = platform.python_version_tuple()
    py_under3 = int(py_version[0]) < 3

    @staticmethod
    def ROL(state, num):
        return ((state << num) | (state >> (32-num)))&0xffffffff

    @staticmethod
    def ROR(state, num):
        return ((state >> num) | (state << (32-num)))&0xffffffff

    @staticmethod
    def xorAr(lhsAr, rhsAr):
        # like (lhsAr ^ rhsAr)

        #assume len(lhsAr) <= len(rhsAr) <= 16

        bLen = min(len(lhsAr), 16)
        aLen = min(len(rhsAr), bLen)
        retVal = bytearray(16)

        for i in range(aLen):
            retVal[i] = lhsAr[i] ^ rhsAr[i]
        for i in range(aLen, bLen):
            retVal[i] = lhsAr[i]

        return retVal

    @staticmethod
    def to_bytearray(obj, obj_name='', encoding='utf-8', forcecopy=False):
        if obj is None:
            raise AttributeError("`%s` is None"%obj_name)
        if type(obj) == bytearray:
            if forcecopy:
                return bytearray(obj)
            return obj
        if type(obj) == str and str != bytes:
            return bytearray(obj,encoding)
        elif type(obj) in (int,float):
            raise AttributeError("`%s` must be a bytes-like object"%obj_name)
        else:
            return bytearray(obj)

    def __init__(self, key):

        if isinstance(key, LEA):
            old_lea = key
            self.rounds = old_lea.rounds
            self.rk = old_lea.rk
            return
        if isinstance(key, CipherMode):
            old_lea = CipherMode.lea
            self.rounds = old_lea.rounds
            self.rk = old_lea.rk
            return

        key_size = len(key)
        if key_size == SIZE_128: rounds = 24
        elif key_size == SIZE_192: rounds = 28
        elif key_size == SIZE_256: rounds = 32
        else: raise AttributeError('Improper key size: %d'%key_size)

        self.rounds = rounds
        # LEA delta


        T = [0] * 8
        mk_len = len(key)
        mk=LEA.to_bytearray(key)
        self.rk = [[0 for x in range(6)] for x in range(32)]
        self.rounds = (mk_len >> 1) + 16
        T[0], T[1], T[2], T[3] = struct.unpack('<LLLL',mk[:16])

        if mk_len == 16:
            for i in range(0, self.rounds, 1):
                temp = self.ROL(self.delta[i & 3], i)

                self.rk[i][0] = T[0] = self.ROL((T[0] + temp) & 0xffffffff, 1)
                self.rk[i][1] = self.rk[i][3] = self.rk[i][5] = T[1] = self.ROL((T[1] + self.ROL(temp, 1)) & 0xffffffff, 3)
                self.rk[i][2] = T[2] = self.ROL((T[2] + self.ROL(temp, 2)) & 0xffffffff, 6)
                self.rk[i][4] = T[3] = self.ROL((T[3] + self.ROL(temp, 3)) & 0xffffffff, 11)

        elif mk_len == 24:
            T[4], T[5] = struct.unpack('<LL',mk[16:24])

            for i in range(0, self.rounds, 1):
                temp = self.ROL(self.delta[i % 6], i)

                self.rk[i][0] = T[0] = self.ROL((T[0] + temp) & 0xffffffff, 1)
                self.rk[i][1] = T[1] = self.ROL((T[1] + self.ROL(temp, 1)) & 0xffffffff, 3)
                self.rk[i][2] = T[2] = self.ROL((T[2] + self.ROL(temp, 2)) & 0xffffffff, 6)
                self.rk[i][3] = T[3] = self.ROL((T[3] + self.ROL(temp, 3)) & 0xffffffff, 11)
                self.rk[i][4] = T[4] = self.ROL((T[4] + self.ROL(temp, 4)) & 0xffffffff, 13)
                self.rk[i][5] = T[5] = self.ROL((T[5] + self.ROL(temp, 5)) & 0xffffffff, 17)

        elif mk_len == 32:
            T[4], T[5], T[6], T[7] = struct.unpack('<LLLL',mk[16:32])

            for i in range(0, self.rounds, 1):
                temp = self.ROL(self.delta[i & 7], i & 0x1f)

                self.rk[i][0] = T[(6 * i    ) & 7] = self.ROL((T[(6 * i    ) & 7] + temp) & 0xffffffff, 1)
                self.rk[i][1] = T[(6 * i + 1) & 7] = self.ROL((T[(6 * i + 1) & 7] + self.ROL(temp, 1)) & 0xffffffff, 3)
                self.rk[i][2] = T[(6 * i + 2) & 7] = self.ROL((T[(6 * i + 2) & 7] + self.ROL(temp, 2)) & 0xffffffff, 6)
                self.rk[i][3] = T[(6 * i + 3) & 7] = self.ROL((T[(6 * i + 3) & 7] + self.ROL(temp, 3)) & 0xffffffff, 11)
                self.rk[i][4] = T[(6 * i + 4) & 7] = self.ROL((T[(6 * i + 4) & 7] + self.ROL(temp, 4)) & 0xffffffff, 13)
                self.rk[i][5] = T[(6 * i + 5) & 7] = self.ROL((T[(6 * i + 5) & 7] + self.ROL(temp, 5)) & 0xffffffff, 17)

    # encrypts a 128 bit input block
    def encrypt(self, pt):
        if len(pt) != 16:
            raise AttributeError('length of pt should be 16 not %d'%len(pt))

        #pt = LEA.to_bytearray(pt)
        temp = list(struct.unpack('<LLLL',pt))

        for i in range(0, self.rounds, 4):
            temp[3] = self.ROR(((temp[2] ^ self.rk[i][4]) + (temp[3] ^ self.rk[i][5])) & 0xffffffff, 3)
            temp[2] = self.ROR(((temp[1] ^ self.rk[i][2]) + (temp[2] ^ self.rk[i][3])) & 0xffffffff, 5)
            temp[1] = self.ROL(((temp[0] ^ self.rk[i][0]) + (temp[1] ^ self.rk[i][1])) & 0xffffffff, 9)
            i += 1
            temp[0] = self.ROR(((temp[3] ^ self.rk[i][4]) + (temp[0] ^ self.rk[i][5])) & 0xffffffff, 3)
            temp[3] = self.ROR(((temp[2] ^ self.rk[i][2]) + (temp[3] ^ self.rk[i][3])) & 0xffffffff, 5)
            temp[2] = self.ROL(((temp[1] ^ self.rk[i][0]) + (temp[2] ^ self.rk[i][1])) & 0xffffffff, 9)
            i += 1
            temp[1] = self.ROR(((temp[0] ^ self.rk[i][4]) + (temp[1] ^ self.rk[i][5])) & 0xffffffff, 3)
            temp[0] = self.ROR(((temp[3] ^ self.rk[i][2]) + (temp[0] ^ self.rk[i][3])) & 0xffffffff, 5)
            temp[3] = self.ROL(((temp[2] ^ self.rk[i][0]) + (temp[3] ^ self.rk[i][1])) & 0xffffffff, 9)
            i += 1
            temp[2] = self.ROR(((temp[1] ^ self.rk[i][4]) + (temp[2] ^ self.rk[i][5])) & 0xffffffff, 3)
            temp[1] = self.ROR(((temp[0] ^ self.rk[i][2]) + (temp[1] ^ self.rk[i][3])) & 0xffffffff, 5)
            temp[0] = self.ROL(((temp[3] ^ self.rk[i][0]) + (temp[0] ^ self.rk[i][1])) & 0xffffffff, 9)

        ct = bytearray(struct.pack('<LLLL',temp[0], temp[1], temp[2], temp[3]))
        return ct

    # decrypts a 128 bit input block
    def decrypt(self, ct):
        ct = LEA.to_bytearray(ct)
        if len(ct) != 16:
            raise AttributeError('length of ct should be 16 not %d'%len(ct))

        temp = list(struct.unpack('<LLLL',ct))

        for i in range(self.rounds - 1, 0, -4):
            temp[0] = ((self.ROR(temp[0], 9) - (temp[3] ^ self.rk[i][0])) & 0xffffffff) ^ self.rk[i][1]
            temp[1] = ((self.ROL(temp[1], 5) - (temp[0] ^ self.rk[i][2])) & 0xffffffff) ^ self.rk[i][3]
            temp[2] = ((self.ROL(temp[2], 3) - (temp[1] ^ self.rk[i][4])) & 0xffffffff) ^ self.rk[i][5]
            i -= 1
            temp[3] = ((self.ROR(temp[3], 9) - (temp[2] ^ self.rk[i][0])) & 0xffffffff) ^ self.rk[i][1]
            temp[0] = ((self.ROL(temp[0], 5) - (temp[3] ^ self.rk[i][2])) & 0xffffffff) ^ self.rk[i][3]
            temp[1] = ((self.ROL(temp[1], 3) - (temp[0] ^ self.rk[i][4])) & 0xffffffff) ^ self.rk[i][5]
            i -= 1
            temp[2] = ((self.ROR(temp[2], 9) - (temp[1] ^ self.rk[i][0])) & 0xffffffff) ^ self.rk[i][1]
            temp[3] = ((self.ROL(temp[3], 5) - (temp[2] ^ self.rk[i][2])) & 0xffffffff) ^ self.rk[i][3]
            temp[0] = ((self.ROL(temp[0], 3) - (temp[3] ^ self.rk[i][4])) & 0xffffffff) ^ self.rk[i][5]
            i -= 1
            temp[1] = ((self.ROR(temp[1], 9) - (temp[0] ^ self.rk[i][0])) & 0xffffffff) ^ self.rk[i][1]
            temp[2] = ((self.ROL(temp[2], 5) - (temp[1] ^ self.rk[i][2])) & 0xffffffff) ^ self.rk[i][3]
            temp[3] = ((self.ROL(temp[3], 3) - (temp[2] ^ self.rk[i][4])) & 0xffffffff) ^ self.rk[i][5]

        pt = bytearray(struct.pack('<LLLL',temp[0], temp[1], temp[2], temp[3]))

        return pt