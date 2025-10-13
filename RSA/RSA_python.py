# rsa_template.py
# 说明：
# - 完全通用的 RSA 实现，允许用户输入任意素数 p, q, 选择 e，并加解密任意整数消息 M。
# - 步骤：选择素数 p,q -> 计算 n 与 Phi(n) -> 选择 e (与 Phi(n) 互质) -> 扩展欧几里得求 d -> 加密/解密
# - 支持加密任意整数消息 M，要求 0 <= M < n

from typing import Tuple

def gcd(a: int, b: int) -> int:
    """最大公约数"""
    while b:
        a, b = b, a % b
    return abs(a)

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    扩展欧几里得算法
    返回 (g, x, y) 使得 ax + by = g = gcd(a, b)
    """
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    # 回代
    x = y1
    y = x1 - (a // b) * y1
    return (g, x, y)

def modinv(a: int, m: int) -> int:
    """
    求 a 在模 m 下的乘法逆元：a * a^{-1} ≡ 1 (mod m)
    需要 gcd(a, m) = 1
    """
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"不存在逆元：gcd({a}, {m}) = {g} ≠ 1")
    return x % m

def modexp(base: int, exponent: int, modulus: int) -> int:
    """
    模幂 (square-and-multiply)：计算 (base^exponent) mod modulus
    """
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    e = exponent
    while e > 0:
        if e & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        e >>= 1
    return result

def generate_keys(p: int, q: int, e: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    按文本流程生成公钥/私钥：
    n = p*q, Phi = (p-1)*(q-1)
    选择 e 使 gcd(e, Phi)=1
    求 d = e^{-1} mod Phi
    返回：((n, e), (n, d))
    """
    if p <= 1 or q <= 1:
        raise ValueError("p 与 q 必须为素数且 > 1")
    if p == q:
        raise ValueError("p 与 q 不能相等")
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError(f"选择的 e={e} 与 Phi(n)={phi} 不互质，请更换 e")
    d = modinv(e, phi)
    return (n, e), (n, d)

def encrypt(m: int, pubkey: Tuple[int, int]) -> int:
    """RSA 加密：c = m^e mod n"""
    n, e = pubkey
    if not (0 <= m < n):
        raise ValueError(f"明文 m 必须满足 0 <= m < n (n={n})")
    return modexp(m, e, n)

def decrypt(c: int, privkey: Tuple[int, int]) -> int:
    """RSA 解密：m = c^d mod n"""
    n, d = privkey
    if not (0 <= c < n):
        raise ValueError(f"密文 c 必须满足 0 <= c < n (n={n})")
    return modexp(c, d, n)

def run_rsa_example():
    """
    获取用户输入的 p, q, e，并计算公钥和私钥，演示加解密过程。
    """
    print("=== RSA 密钥生成与加解密示例 ===")
    
    # 获取用户输入
    p = int(input("请输入素数 p: "))
    q = int(input("请输入素数 q: "))
    e = int(input("请输入公钥指数 e: "))

    # 生成密钥对
    (n, e), (n2, d) = generate_keys(p, q, e)
    assert n == n2
    print(f"\n生成的密钥对：")
    print(f"公钥 (e, n) = ({e}, {n})")
    print(f"私钥 (d, n) = ({d}, {n})")
    
    # 获取并加密用户输入的明文 M
    M = int(input("\n请输入明文 M (0 <= M < n): "))
    C = encrypt(M, (n, e))
    print(f"\n加密后的密文 C = {C}")
    
    # 解密密文
    M2 = decrypt(C, (n, d))
    print(f"\n解密后的明文 M' = {M2}")

    # 验证加解密是否一致
    print(f"\n验证：加解密是否一致：", "OK ✅" if M == M2 else "不一致 ❌")

if __name__ == "__main__":
    # 运行通用的 RSA 示例，用户可以输入 p, q, e 和明文 M
    run_rsa_example()
