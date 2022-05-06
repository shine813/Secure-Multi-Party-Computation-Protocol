<h1 align='center' >安全多方计算协议</h1>


---

## 项目背景

安全多方计算（Secure Multi-Party Computation）的研究主要是针对无可信第三方的情况下，如何安全地计算一个约定函数的问题。安全多方计算是电子选举、门限签名以及电子拍卖等诸多应用得以实施的密码学基础。

一个安全多方计算协议，如果对于拥有无限计算能力攻击者而言是安全的，则称作是信息论安全的或无条件安全的；如果对于拥有多项式计算能力的攻击者是安全的，则称为是密码学安全的或条件安全的。

已有的结果证明了在无条件安全模型下，当且仅当恶意参与者的人数少于总人数的1/3时，安全的方案才存在。而在条件安全模型下，当且仅当恶意参与者的人数少于总人数的一半时，安全的方案才存在。

安全多方计算起源于1982年[姚期智](https://baike.baidu.com/item/姚期智)的百万富翁问题。后来Oded Goldreich有比较细致系统的论述。

基于phe库 (Paillier Homomorphic Encryption) 的安全多方计算协议实现，包含：

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

安装`smpcp`库：`pip install smpcp`

### 生成密钥

`public_key, secret_key = phe.generate_paillier_keypair(n_length=2048)`



### 安全乘法协议

---

## 项目测试

---

## 联系方式

