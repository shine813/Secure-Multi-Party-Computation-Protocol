#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
@Version: 2.0.0
@Project: Secure-Multi-Party-Computation-Protocol
@Author: Zhan Shi
@Time  : 2022/5/4 15:54
@File: test_smpcp.py
@License: MIT
"""
import random
import sys
import unittest

import gmpy2
import phe

from smpcp.smpcp import CloudPlatform, CloudPlatformThird, SecureMultiPartyComputationProtocol

sys.path.append("test_case/")  # 添加测试文件路径

key_length = 2048  # TODO 密钥长度

public_key, secret_key = phe.generate_paillier_keypair(n_length=key_length)  # 生成密钥对

cloud1 = CloudPlatform(public_key=public_key)  # 云服务器1
cloud2 = CloudPlatformThird(public_key=public_key, secret_key=secret_key)  # 云服务器2

protocol = SecureMultiPartyComputationProtocol(c1=cloud1, c2=cloud2)  # 安全多方计算协议类


class SMPCPTest(unittest.TestCase):
    """
    安全多方计算协议测试类
    """

    def setUp(self):
        """
        测试前
        """
        # 生成浮点数
        self.float1 = int(
            gmpy2.mpz_random(gmpy2.random_state(
                int(gmpy2.mpz_random(gmpy2.random_state(random.SystemRandom().randint(1, 0xffffffff)),
                                     key_length))), key_length)) * random.uniform(0.1, 1.0)
        self.float2 = int(
            gmpy2.mpz_random(gmpy2.random_state(
                int(gmpy2.mpz_random(gmpy2.random_state(random.SystemRandom().randint(1, 0xffffffff)), key_length))),
                key_length)) * random.uniform(0.1, 1.0)
        self.float_n1 = protocol.encode(public_key.encrypt(self.float1))
        self.float_n2 = public_key.encrypt(self.float2)
        # 生成整数
        self.int1 = int(gmpy2.mpz_random(gmpy2.random_state(
            int(gmpy2.mpz_random(gmpy2.random_state(random.SystemRandom().randint(1, 0xffffffff)), key_length))),
            key_length))
        self.int2 = int(gmpy2.mpz_random(gmpy2.random_state(
            int(gmpy2.mpz_random(gmpy2.random_state(random.SystemRandom().randint(1, 0xffffffff)), key_length))),
            key_length))
        self.int_n1 = protocol.encode(public_key.encrypt(self.int1))
        self.int_n2 = public_key.encrypt(self.int2)
        return super().setUp()

    def tearDown(self):
        """
        测试后
        """
        return super().tearDown()

    # TODO 安全乘法协议测试
    # @unittest.skip('跳过安全乘法协议')
    def test_mul(self):
        """
        安全乘法协议
        """
        # 浮点乘法测试：经过测试，最高支持8位浮点乘法
        self.assertEqual(round(self.float1 * self.float2, 8),
                         round(secret_key.decrypt(self.float_n1 * self.float_n2), 8))

        # 整数乘法测试：经过测试，无明显问题
        self.assertEqual(self.int1 * self.int2, secret_key.decrypt(self.int_n1 * self.int_n2))

    # TODO 安全除法协议测试
    # @unittest.skip('跳过安全除法协议')
    def test_div(self):
        """
        安全除法协议
        """
        # 浮点除法测试：经过测试，最高支持10位浮点除法
        self.assertEqual(round(self.float1 / self.float2, 10),
                         round(secret_key.decrypt(self.float_n1 / self.float_n2), 10))

        # 整数除法测试：经过测试，最高支持10位整数除法
        self.assertEqual(round(self.int1 / self.int2, 10), round(secret_key.decrypt(self.int_n1 / self.int_n2), 10))

    # TODO 安全最值计算协议测试
    # @unittest.skip('跳过安全最值计算协议')
    def test_optimum(self):
        """
        安全最值计算协议
        """
        mode = 'max' if random.random() > 0.5 else 'min'
        if mode == 'max':
            # 浮点最大值计算测试：经过测试，无明显问题
            self.assertEqual(max(self.float1, self.float2),
                             secret_key.decrypt(self.float_n1.optimum(self.float_n2, 'max')))

            # 整数最大值计算测试：经过测试，无明显问题
            self.assertEqual(max(self.int1, self.int2), secret_key.decrypt(self.int_n1.optimum(self.int_n2, 'max')))
        else:
            # 浮点最小值计算测试：经过测试，无明显问题
            self.assertEqual(min(self.float1, self.float2),
                             secret_key.decrypt(self.float_n1.optimum(self.float_n2, 'min')))

            # 整数最小值计算测试：经过测试，无明显问题
            self.assertEqual(min(self.int1, self.int2), secret_key.decrypt(self.int_n1.optimum(self.int_n2, 'min')))

    # TODO 安全奇偶性判断协议测试
    # @unittest.skip('跳过安全奇偶性判断协议')
    def test_parity(self):
        """
        安全奇偶性判断协议
        """
        # 整数奇偶性判断测试：经过测试，无明显问题
        self.assertEqual(self.int1 % 2, secret_key.decrypt(self.int_n1.parity()))

    # TODO 安全二进制分解协议测试
    # @unittest.skip('跳过安全二进制分解协议')
    def test_bit_dec(self):
        """
        安全二进制分解协议
        """
        # 整数二进制分解测试：经过测试，无明显问题
        bit = len(bin(self.int1).split('b')[1])
        result = ''.join([str(secret_key.decrypt(v)) for v in self.int_n1.bit_dec(bit)])
        self.assertEqual(bin(self.int1).split('b')[1], result)

    # TODO 安全二进制与协议测试
    # @unittest.skip('跳过安全二进制与协议')
    def test_and(self):
        """
        安全二进制与协议
        """
        bit1 = random.SystemRandom().randint(0, 1)
        bit2 = random.SystemRandom().randint(0, 1)
        bit_n1 = protocol.encode(public_key.encrypt(bit1))
        bit_n2 = public_key.encrypt(bit2)
        # 二进制或测试：经过测试，无明显问题
        self.assertEqual(bit1 & bit2, secret_key.decrypt(bit_n1 & bit_n2))

    # TODO 安全二进制或协议测试
    # @unittest.skip('跳过安全二进制或协议')
    def test_or(self):
        """
        安全二进制或协议
        """
        bit1 = random.SystemRandom().randint(0, 1)
        bit2 = random.SystemRandom().randint(0, 1)
        bit_n1 = protocol.encode(public_key.encrypt(bit1))
        bit_n2 = public_key.encrypt(bit2)
        # 二进制或测试：经过测试，无明显问题
        self.assertEqual(bit1 | bit2, secret_key.decrypt(bit_n1 | bit_n2))

    # TODO 安全二进制非协议测试
    # @unittest.skip('跳过安全二进制非协议')
    def test_bit_not(self):
        """
        安全二进制非协议
        """
        bit1 = random.SystemRandom().randint(0, 1)
        bit_n1 = protocol.encode(public_key.encrypt(bit1))
        # 二进制或测试：经过测试，无明显问题
        self.assertEqual(1 - bit1, secret_key.decrypt(bit_n1.bit_not()))

    # TODO 安全二进制异或协议测试
    # @unittest.skip('跳过安全二进制异或协议')
    def test_xor(self):
        """
        安全二进制异或协议
        """
        bit1 = random.SystemRandom().randint(0, 1)
        bit2 = random.SystemRandom().randint(0, 1)
        bit_n1 = protocol.encode(public_key.encrypt(bit1))
        bit_n2 = public_key.encrypt(bit2)
        # 二进制或测试：经过测试，无明显问题
        self.assertEqual(bit1 ^ bit2, secret_key.decrypt(bit_n1 ^ bit_n2))

    # TODO 安全相等协议测试
    # @unittest.skip('跳过安全相等协议')
    def test_eq(self):
        """
        安全相等协议
        """
        # 浮点数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.float1 == self.float1 else 0,
                         secret_key.decrypt(self.float_n1 == self.float_n1.decode()))

        # 整数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.int1 == self.int1 else 0, secret_key.decrypt(self.int_n1 == self.int_n1.decode()))

    # TODO 安全不相等协议测试
    # @unittest.skip('跳过安全不相等协议')
    def test_ne(self):
        """
        安全不相等协议
        """
        # 浮点数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.float1 != self.float2 else 0, secret_key.decrypt(self.float_n1 != self.float_n2))

        # 整数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.int1 != self.int2 else 0, secret_key.decrypt(self.int_n1 != self.int_n2))

    # TODO 安全大于协议测试
    # @unittest.skip('跳过安全大于协议')
    def test_gt(self):
        """
        安全大于协议
        """
        # 浮点数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.float1 > self.float2 else 0, secret_key.decrypt(self.float_n1 > self.float_n2))

        # 整数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.int1 > self.int2 else 0, secret_key.decrypt(self.int_n1 > self.int_n2))

    # TODO 安全大于等于协议测试
    # @unittest.skip('跳过安全大于等于协议')
    def test_ge(self):
        """
        安全大于等于协议
        """
        # 浮点数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.float1 >= self.float2 else 0, secret_key.decrypt(self.float_n1 >= self.float_n2))

        # 整数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.int1 >= self.int2 else 0, secret_key.decrypt(self.int_n1 >= self.int_n2))

    # TODO 安全小于协议测试
    # @unittest.skip('跳过安全小于协议')
    def test_lt(self):
        """
        安全小于协议
        """
        # 浮点数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.float1 < self.float2 else 0, secret_key.decrypt(self.float_n1 < self.float_n2))

        # 整数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.int1 < self.int2 else 0, secret_key.decrypt(self.int_n1 < self.int_n2))

    # TODO 安全小于等于协议测试
    # @unittest.skip('跳过安全小于等于协议')
    def test_le(self):
        """
        安全小于等于协议
        """
        # 浮点数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.float1 <= self.float2 else 0, secret_key.decrypt(self.float_n1 <= self.float_n2))

        # 整数相等测试：经过测试，极少数情况下，浮点数会影响结果
        self.assertEqual(1 if self.int1 <= self.int2 else 0, secret_key.decrypt(self.int_n1 <= self.int_n2))
