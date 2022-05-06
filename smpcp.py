#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
@Version: 0.0.1
@Project: Secure-Multi-Party-Computation-Protocol
@Author: Zhan Shi
@Time  : 2022/5/3 12:23
@File: smpcp.py
@License: MIT
"""
import random

import gmpy2


class SecureMultiPartyComputationProtocol:
    """
    安全多方计算协议类
    """

    def __init__(self, c1, c2, cipher=None):
        """
        安全多方计算协议类 定义
        :param c1: 云服务器
        :param c2: 第三方云服务器
        :param cipher: 密文
        """
        self.c1 = c1
        self.c2 = c2
        self.cipher = cipher

    def encode(self, encrypted_number):
        """
        安全多方计算协议类 编码
        :param encrypted_number: 加密数字
        :return: 编码后的加密数字
        """
        return SecureMultiPartyComputationProtocol(c1=self.c1, c2=self.c2, cipher=encrypted_number)

    def decode(self):
        """
        安全多方计算协议类 解码
        :return: 解码后的加密数字
        """
        return self.cipher

    def __mul__(self, other):
        """
        TODO 安全多方计算协议类 安全乘法协议
        :param other: 密文
        :return: 安全乘法协议结果 E(self.cipher * other)
        """
        return self.c1.mul(self.cipher, other, self.c2)

    def __truediv__(self, other):
        """
        TODO 安全多方计算协议类 安全除法协议
        :param other: 密文
        :return: 安全除法协议结果 E(self.cipher / other)
        """
        return self.c1.truediv(self.cipher, other, self.c2)

    def optimum(self, other, mode):
        """
        TODO 安全多方计算协议类 安全最值计算协议
        :param other: 密文
        :param mode: 'max' or 'min'
        :return: 安全最值计算协议结果 E(max(self.cipher, other)) or E(min(self.cipher, other))
        """
        return self.c1.optimum(self.cipher, other, self.c2, mode)

    def parity(self):
        """
        TODO 安全多方计算协议类 安全奇偶性判断协议
        :return: 安全奇偶性判断协议结果 奇数: E(1) 偶数: E(0)
        """
        return self.c1.parity(self.cipher, self.c2)

    def bit_dec(self, bit):
        """
        TODO 安全多方计算协议类 安全二进制分解协议
        :param bit: 位数
        :return: 安全二进制分解协议结果 self.cipher的二进制数列 -> [E(1) or E(0), ...] 长度为bit
        """
        return self.c1.bit_dec(self.cipher, bit, self.c2)

    def __and__(self, other):
        """
        TODO 安全多方计算协议类 安全二进制与协议
        ! 只能用于二进制数
        :param other: 密文
        :return: 安全二进制与协议结果 E(self.cipher & other)
        """
        return self.c1.bit_and(self.cipher, other, self.c2)

    def __or__(self, other):
        """
        TODO 安全多方计算协议类 安全二进制或协议
        ! 只能用于二进制数
        :param other: 密文
        :return: 安全二进制或协议结果 E(self.cipher | other)
        """
        return self.c1.bit_or(self.cipher, other, self.c2)

    def bit_not(self):
        """
        TODO 安全多方计算协议类 安全二进制非协议
        ! 只能用于二进制数
        :return: 安全二进制非协议结果 E(!self.cipher)
        """
        return self.c1.bit_not(self.cipher)

    def __xor__(self, other):
        """
        TODO 安全多方计算协议类 安全二进制异或协议
        ! 只能用于二进制数
        :return: 安全二进制异或协议结果 E(self.cipher ^ other)
        """
        return self.c1.bit_xor(self.cipher, other, self.c2)

    def __eq__(self, other):
        """
        TODO 安全多方计算协议类 安全相等协议
        :param other: 密文
        :return: 安全相等协议结果 E(self.cipher == other)
        """
        return self.c1.eq(self.cipher, other, self.c2)

    def __ne__(self, other):
        """
        TODO 安全多方计算协议类 安全不相等协议
        :param other: 密文
        :return: 安全不相等协议结果 E(self.cipher != other)
        """
        return self.c1.ne(self.cipher, other, self.c2)

    def __gt__(self, other):
        """
        TODO 安全多方计算协议类 安全大于协议
        :param other: 密文
        :return: 安全大于协议结果 E(self.cipher > other)
        """
        return self.c1.gt(self.cipher, other, self.c2)

    def __ge__(self, other):
        """
        TODO 安全多方计算协议类 安全大于等于协议
        :param other: 密文
        :return: 安全大于等于协议结果 E(self.cipher >= other)
        """
        return self.c1.ge(self.cipher, other, self.c2)

    def __lt__(self, other):
        """
        TODO 安全多方计算协议类 安全小于协议
        :param other: 密文
        :return: 安全小于协议结果 E(self.cipher < other)
        """
        return self.c1.lt(self.cipher, other, self.c2)

    def __le__(self, other):
        """
        TODO 安全多方计算协议类 安全小于等于协议
        :param other: 密文
        :return: 安全小于等于协议结果 E(self.cipher <= other)
        """
        return self.c1.le(self.cipher, other, self.c2)


class CloudPlatform:
    """
    云服务器类
    """

    def __init__(self, public_key):
        """
        云服务器类 定义
        :param public_key: 公钥
        """
        self.public_key = public_key
        self.key_length = len(str(self.public_key.n))

    def mul(self, c1, c2, cloud_platform_third):
        """
        TODO 云服务器类 安全乘法协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :return: 加密乘法结果
        """
        r1 = self._generate_random()
        r2 = self._generate_random()

        h1 = c1 + r1
        h2 = c2 + r2

        return cloud_platform_third.mul(h1, h2) - (c1 * r2 + c2 * r1 + r1 * r2)

    def truediv(self, c1, c2, cloud_platform_third):
        """
        TODO 云服务器类 安全除法协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :return: 加密除法结果
        """
        r1 = self._generate_random()
        r2 = self._generate_random()

        h1 = c1 * r1 + c2 * r1 * r2
        h2 = c2 * r1

        return cloud_platform_third.truediv(h1, h2) - r2

    def optimum(self, c1, c2, cloud_platform_third, mode):
        """
        TODO 云服务器类 安全最值计算协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :param mode: 'max' or 'min'
        :return: 加密最值计算结果
        """
        r1 = self._generate_random()
        r2 = self._generate_random()
        r3 = self._generate_random()

        if random.random() > 5e-1:
            h1 = (c1 - c2) * r1
            h2 = c1 + r2
            h3 = c2 + r3
        else:
            h1 = (c2 - c1) * r1
            h2 = c2 + r2
            h3 = c1 + r3

        alpha, beta = cloud_platform_third.optimum(h1, h2, h3, mode)

        return c1 + c2 - beta + alpha * r3 + (1 - alpha) * r2

    def parity(self, c, cloud_platform_third):
        """
        TODO 云服务器类 安全奇偶性判断协议
        :param c: 密文
        :param cloud_platform_third: 第三方云服务器
        :return: 加密奇偶性判断结果
        """
        r = self._generate_random()
        h = c + r
        alpha = cloud_platform_third.parity(h)

        return alpha if r % 2 == 0 else 1 - alpha

    def bit_dec(self, c, bit, cloud_platform_third):
        """
        TODO 云服务器类 安全二进制分解协议
        :param c: 密文
        :param bit: 位数
        :param cloud_platform_third: 第三方云服务器
        :return: 加密二进制分解结果
        """
        sigma = 5e-1
        result = []
        for i in range(bit):
            result.append(self.parity(c, cloud_platform_third))
            zeta = c - result[i]
            c = zeta * sigma
        result.reverse()

        return result

    def bit_and(self, c1, c2, cloud_platform_third):
        """
        TODO 云服务器类 安全二进制与协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :return: 加密二进制与结果
        """
        return self.mul(c1, c2, cloud_platform_third)

    def bit_or(self, c1, c2, cloud_platform_third):
        """
        TODO 云服务器类 安全二进制或协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :return: 加密二进制或结果
        """
        return c1 + c2 - self.bit_and(c1, c2, cloud_platform_third)

    @staticmethod
    def bit_not(c):
        """
        TODO 云服务器类 安全二进制非协议
        :param c: 密文
        :return: 加密二进制非结果
        """
        return 1 - c

    def bit_xor(self, c1, c2, cloud_platform_third):
        """
        TODO 云服务器类 安全二进制异或协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :return: 加密二进制异或结果
        """
        return c1 + c2 - 2 * self.mul(c1, c2, cloud_platform_third)

    def eq(self, c1, c2, cloud_platform_third):
        """
        TODO 云服务器类 安全相等协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :return: 加密相等结果
        """
        sigma = -1 if random.random() > 5e-1 else 1
        r1 = self._generate_random()
        r2 = self._generate_random()
        if r2 > r1:
            r2, r1 = r1, r2
        alpha = r1 * sigma * self.mul(c1 - c2, c1 - c2, cloud_platform_third) - sigma * r2

        return cloud_platform_third.eq(alpha) if sigma == 1 else 1 - cloud_platform_third.eq(alpha)

    def ne(self, c1, c2, cloud_platform_third):
        """
        TODO 云服务器类 安全不相等协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :return: 加密不相等结果
        """
        return 1 - self.eq(c1, c2, cloud_platform_third)

    def gt(self, c1, c2, cloud_platform_third):
        """
        TODO 云服务器类 安全大于协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :return: 加密大于结果
        """
        sigma = -1 if random.random() > 5e-1 else 1
        r1 = self._generate_random()
        r2 = self._generate_random()
        (r2, r1) = (r1, r2) if r2 > r1 else (r2, r1)
        alpha = r1 * sigma * (c2 - c1) + sigma * r2

        return cloud_platform_third.eq(alpha) if sigma == 1 else 1 - cloud_platform_third.eq(alpha)

    def ge(self, c1, c2, cloud_platform_third):
        """
        TODO 云服务器类 安全大于等于协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :return: 加密大于等于结果
        """
        return self.bit_or(self.eq(c1, c2, cloud_platform_third), self.gt(c1, c2, cloud_platform_third),
                           cloud_platform_third)

    def lt(self, c1, c2, cloud_platform_third):
        """
        TODO 云服务器类 安全小于协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :return: 加密小于结果
        """
        sigma = -1 if random.random() > 5e-1 else 1
        r1 = self._generate_random()
        r2 = self._generate_random()
        (r2, r1) = (r1, r2) if r2 > r1 else (r2, r1)
        alpha = r1 * sigma * (c1 - c2) + sigma * r2

        return cloud_platform_third.eq(alpha) if sigma == 1 else 1 - cloud_platform_third.eq(alpha)

    def le(self, c1, c2, cloud_platform_third):
        """
        TODO 云服务器类 安全小于等于协议
        :param c1: 密文1
        :param c2: 密文2
        :param cloud_platform_third: 第三方云服务器
        :return: 加密小于等于结果
        """
        return self.bit_or(self.eq(c1, c2, cloud_platform_third), self.lt(c1, c2, cloud_platform_third),
                           cloud_platform_third)

    def _generate_random(self):
        """
        云服务器 随机数生成
        :return: 密钥长度的随机数
        """
        return int(gmpy2.mpz_random(gmpy2.random_state(random.SystemRandom().randint(1, 0xffffffff)), self.key_length))


class CloudPlatformThird:
    """
    第三方云服务器类
    """

    def __init__(self, public_key, secret_key):
        """
        第三方云服务器类 定义
        :param public_key: 公钥
        :param secret_key: 私钥
        """
        self.public_key = public_key
        self.secret_key = secret_key

    def mul(self, h1, h2):
        """
        TODO 第三方云服务器类 安全乘法协议
        :param h1: 参数1
        :param h2: 参数2
        :return: 安全乘法协议结果
        """
        return self.public_key.encrypt(self.secret_key.decrypt(h1) * self.secret_key.decrypt(h2))

    def truediv(self, h1, h2):
        """
        TODO 第三方云服务器类 安全除法协议
        :param h1: 参数1
        :param h2: 参数2
        :return: 安全除法协议结果
        """
        h2 = self.secret_key.decrypt(h2)
        if h2 != 0:
            return self.public_key.encrypt(self.secret_key.decrypt(h1) / h2)
        else:
            assert ValueError("Divisor cannot be 0")

    def optimum(self, h1, h2, h3, mode):
        """
        TODO 第三方云服务器类 安全最值计算协议
        :param h1: 参数
        :param h2: 参数
        :param h3: 参数
        :param mode: 'max' or 'min'
        :return: 安全最值计算协议结果
        """
        mode = self.secret_key.decrypt(h1) > 0 if mode == 'max' else self.secret_key.decrypt(h1) < 0
        alpha = 1 if mode else 0

        return self.public_key.encrypt(alpha), h3 if alpha == 1 else h2

    def parity(self, h):
        """
        TODO 第三方云服务器类 安全奇偶性判断协议
        :param h: 参数
        :return: 安全奇偶性判断协议结果
        """
        return self.public_key.encrypt(0) if self.secret_key.decrypt(h) % 2 == 0 else self.public_key.encrypt(1)

    def eq(self, h):
        """
        TODO 第三方云服务器类 安全相等协议
        :param h: 参数
        :return: 安全相等协议结果
        """
        return self.public_key.encrypt(1) if self.secret_key.decrypt(h) < 0 else self.public_key.encrypt(0)
