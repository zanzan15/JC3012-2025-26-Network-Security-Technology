import random
from typing import Dict, Tuple

def is_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin素数检测算法，k为检测次数（值越大越可靠）"""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False
    
    # 将n-1分解为d*2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    # 进行k次检测
    for _ in range(k):
        a = random.randint(2, min(n - 2, 1 << 20))  # 随机选择底数a
        x = pow(a, d, n)  # 计算a^d mod n
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            # 若未通过检测，n为合数
            return False
    return True

def generate_prime(bits: int = 256) -> int:
    """生成指定位数的大素数（默认256位，满足安全性要求）"""
    while True:
        # 生成一个bits位的随机数（确保为奇数）
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # 确保最高位为1（满足位数）且最低位为1（奇数）
        if is_prime(p):
            return p

def find_primitive_root(p: int) -> int:
    """查找素数p的本原根（生成元g）"""
    if p == 2:
        return 1
    # 分解p-1的质因数
    factors = set()
    phi = p - 1
    temp = phi
    # 提取2作为因子
    while temp % 2 == 0:
        factors.add(2)
        temp //= 2
    # 提取奇数因子
    i = 3
    while i * i <= temp:
        while temp % i == 0:
            factors.add(i)
            temp //= i
        i += 2
    if temp > 1:
        factors.add(temp)
    
    # 检测g是否为p的本原根
    for g in range(2, p):
        if all(pow(g, phi // factor, p) != 1 for factor in factors):
            return g
    return None

def generate_dh_parameters() -> Tuple[int, int]:
    """生成DH算法的公开参数：大素数p和本原根g"""
    p = generate_prime(bits=256)
    g = find_primitive_root(p)
    return p, g

def generate_key_pair(p: int, g: int) -> Tuple[int, int]:
    """
    生成DH密钥对
    返回：(私钥, 公钥)
    """
    private_key = random.randint(2, p - 2)  # 私钥（1 < 私钥 < p-1）
    public_key = pow(g, private_key, p)     # 公钥 = g^私钥 mod p
    return private_key, public_key

def compute_shared_secret(other_public_key: int, private_key: int, p: int) -> int:
    """
    计算共享密钥
    other_public_key: 对方的公钥
    private_key: 自己的私钥
    p: 公开素数
    返回：共享密钥
    """
    return pow(other_public_key, private_key, p)

def run_dh_example() -> None:
    """
    Diffie-Hellman密钥交换示例
    演示完整的密钥交换过程，包括参数生成、密钥对生成和共享密钥计算
    """
    print("=== Diffie-Hellman 密钥交换示例 ===")
    
    # 生成公开参数
    p, g = generate_dh_parameters()
    print(f"\n生成的公开参数：")
    print(f"大素数 p = {p}")
    print(f"本原根 g = {g}")
    
    # 客户端生成密钥对
    client_private, client_public = generate_key_pair(p, g)
    print(f"\n客户端密钥对：")
    print(f"客户端私钥 (保密) = {client_private}")
    print(f"客户端公钥 (公开) = {client_public}")
    
    # 服务器生成密钥对
    server_private, server_public = generate_key_pair(p, g)
    print(f"\n服务器密钥对：")
    print(f"服务器私钥 (保密) = {server_private}")
    print(f"服务器公钥 (公开) = {server_public}")
    
    # 计算共享密钥
    client_shared = compute_shared_secret(server_public, client_private, p)
    server_shared = compute_shared_secret(client_public, server_private, p)
    
    print(f"\n计算的共享密钥：")
    print(f"客户端计算的共享密钥 = {client_shared}")
    print(f"服务器计算的共享密钥 = {server_shared}")
    
    # 验证共享密钥一致性
    print(f"\n验证：加解密是否一致：", "OK ✅" if client_shared == server_shared else "不一致 ❌")

if __name__ == "__main__":
    # 运行DH示例
    run_dh_example()
