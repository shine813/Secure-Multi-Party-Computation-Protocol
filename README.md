<h1 align='center' >安全多方计算协议</h1>


---
<a href="https://github.com/shine813/Secure-Multi-Party-Computation-Protocol"><img src="https://img.shields.io/badge/smpcp-2.0.2-green"></a>


<a href="https://pypi.org/project/smpcp/"><img src="https://img.shields.io/badge/pypi-2.0.2-blue" alt="pypi"></a>

---

## 项目背景

安全多方计算（Secure Multi-Party Computation）的研究主要是针对无可信第三方的情况下，如何安全地计算一个约定函数的问题。安全多方计算是电子选举、门限签名以及电子拍卖等诸多应用得以实施的密码学基础。

一个安全多方计算协议，如果对于拥有无限计算能力攻击者而言是安全的，则称作是信息论安全的或无条件安全的；如果对于拥有多项式计算能力的攻击者是安全的，则称为是密码学安全的或条件安全的。

已有的结果证明了在无条件安全模型下，当且仅当恶意参与者的人数少于总人数的1/3时，安全的方案才存在。而在条件安全模型下，当且仅当恶意参与者的人数少于总人数的一半时，安全的方案才存在。

安全多方计算起源于1982年[姚期智](https://baike.baidu.com/item/姚期智)的百万富翁问题。后来Oded Goldreich有比较细致系统的论述。

基于[phe](https://github.com/data61/python-paillier)库 (Paillier Homomorphic Encryption) 的安全多方计算协议实现，包含：

- 安全乘法协议
- 安全除法协议
- 安全最大值计算协议
- 安全最小值计算协议
- 安全奇偶性判断协议
- 安全二进制分解协议
- 安全二进制与协议
- 安全二进制或协议
- 安全二进制非协议
- 安全二进制异或协议
- 安全相等协议
- 安全不相等协议
- 安全大于协议
- 安全大于等于协议
- 安全小于协议
- 安全小于等于协议

---

## 项目环境

- `python3.8`
- `gmpy2>=2.0.8`
- `pandas>=1.2.4`
- `phe>=1.4.0`
- `tqdm>=4.59.0`
- `numpy>=1.20.2`

详见`requirements.txt`。

---

## 项目示例

### 准备工作

安全依赖环境: `pip install -r requirements.txt`

安装`smpcp`库: `pip install smpcp`

引入`phe`库: `import phe`

引入`smpcp`库: `from smpcp import CloudPlatform, CloudPlatformThird, SecureMultiPartyComputationProtocol`

### 生成密钥

```python
public_key, secret_key = phe.generate_paillier_keypair(n_length=2048)
```

其中`n_length`为密钥长度。

### 定义云服务器

```python
cloud1 = CloudPlatform(public_key=public_key)
cloud2 = CloudPlatformThird(public_key=public_key, secret_key=secret_key)
```

### 定义安全多方计算协议

```python
protocol = SecureMultiPartyComputationProtocol(c1=cloud1, c2=cloud2)
```

### 编码

```python
n1 = protocol.encode(public_key.encrypt(6))
n2 = public_key.encrypt(3)
b1 = protocol.encode(public_key.encrypt(1))
b2 = public_key.encrypt(0)
```

### 解码

```python
assert secret_key.decrypt(n1.decode()) == 6
```

### 安全多方计算协议实现

```python
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
```

详见`example.py`。

---

## 项目测试

经过`Unit Test`测试，测试结果如下：

```python
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
```

详见`test_case/test_smpcp.py`, 项目报告依赖基于`unittest`的[项目](https://github.com/TesterlifeRaymond/BeautifulReport)`test_case/BeautifulReport.py`。

---

## 联系方式

作者：沈阳航空航天大学 数据安全与隐私计算课题组 施展

Github: https://github.com/shine813/

Pypi: https://pypi.org/project/smpcp/

邮箱：phe.zshi@gmail.com

如有问题，可及时联系作者
