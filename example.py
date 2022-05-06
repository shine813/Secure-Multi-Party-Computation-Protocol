#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
@Version: 1.0.0
@Project: Secure-Multi-Party-Computation-Protocol
@Author: Zhan Shi
@Time  : 2022/5/1 09:35
@File: example.py
@License: MIT
"""
import phe

from smpcp import CloudPlatform, CloudPlatformThird, SecureMultiPartyComputationProtocol

# TODO 生成密钥
public_key, secret_key = phe.generate_paillier_keypair(n_length=2048)
# TODO 定义云服务器
cloud1 = CloudPlatform(public_key=public_key)
cloud2 = CloudPlatformThird(public_key=public_key, secret_key=secret_key)
# TODO 定义安全多方计算协议
protocol = SecureMultiPartyComputationProtocol(c1=cloud1, c2=cloud2)

if __name__ == '__main__':
    # TODO 安全多方计算协议编码
    n1 = protocol.encode(public_key.encrypt(6))
    n2 = public_key.encrypt(3)
    b1 = protocol.encode(public_key.encrypt(1))
    b2 = public_key.encrypt(0)
    # TODO 协议解码
    assert secret_key.decrypt(n1.decode()) == 6
    # TODO 安全乘法协议
    assert secret_key.decrypt(n1 * n2) == 18
    # TODO 安全除法协议
    assert secret_key.decrypt(n1 / n2) == 2
    # TODO 安全最大值协议
    assert secret_key.decrypt(n1.optimum(n2, 'max')) == 6
    # TODO 安全最小值协议
    assert secret_key.decrypt(n1.optimum(n2, 'min')) == 3
    # TODO 安全奇偶性判断协议
    assert secret_key.decrypt(n1.parity()) == 0
    assert secret_key.decrypt(protocol.encode(n2).parity()) == 1
    # TODO 安全二进制分解协议
    bit = []
    for v in n1.bit_dec(3):
        bit.append(secret_key.decrypt(v))
    assert bit == [1, 1, 0]
    # TODO 安全二进制与协议
    assert secret_key.decrypt(b1 | b2) == 1
    # TODO 安全二进制或协议
    assert secret_key.decrypt(b1 & b2) == 0
    # TODO 安全二进制非协议
    assert secret_key.decrypt(b1.bit_not()) == 0
    # TODO 安全二进制异或协议
    assert secret_key.decrypt(b1 ^ b2) == 1
    # TODO 安全相等协议
    assert secret_key.decrypt(n1 == n2) == 0
    assert secret_key.decrypt(n1 == n2 * 2) == 1
    # TODO 安全不相等协议
    assert secret_key.decrypt(n1 != n2) == 1
    assert secret_key.decrypt(n1 != n2 * 2) == 0
    # TODO 安全大于协议
    assert secret_key.decrypt(n1 > n2) == 1
    assert secret_key.decrypt(n2 > n1) == 0
    # TODO 安全大于等于协议
    assert secret_key.decrypt(n1 >= n2) == 1
    assert secret_key.decrypt(n2 >= n1) == 0
    # TODO 安全小于协议
    assert secret_key.decrypt(n1 < n2) == 0
    assert secret_key.decrypt(n2 < n1) == 1
    # TODO 安全小于等于协议
    assert secret_key.decrypt(n1 <= n2) == 0
    assert secret_key.decrypt(n2 <= n1) == 1
