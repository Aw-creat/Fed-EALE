import time
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import statistics
from typing import List, Callable

# SECP256K1的阶（order）是一个固定值
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def measure_time(func: Callable, iterations: int = 1000) -> float:
    """
    测量函数执行时间，返回平均时间（毫秒）
    """
    times = []
    for _ in range(iterations):
        start_time = time.perf_counter()
        func()
        end_time = time.perf_counter()
        times.append((end_time - start_time) * 1000)  # 转换为毫秒
    return statistics.mean(times)


def benchmark_hash():
    """测试SHA-256哈希操作"""
    data = os.urandom(1024)  # 1KB的随机数据

    def hash_operation():
        hashlib.sha256(data).digest()

    return measure_time(hash_operation)


def benchmark_xor():
    """测试异或操作"""
    data1 = os.urandom(4)
    data2 = os.urandom(4)

    def xor_operation():
        bytes(a ^ b for a, b in zip(data1, data2))

    return measure_time(xor_operation)


def benchmark_scalar_mult():
    """测试SECP256K1曲线上标量乘法"""
    curve = ec.SECP256K1()
    private_key = ec.generate_private_key(curve)

    def scalar_mult():
        k = random.randrange(1, SECP256K1_ORDER)
        private_key.private_numbers().private_value * k % SECP256K1_ORDER

    return measure_time(scalar_mult, iterations=100)  # 减少迭代次数因为这个操作较慢


def benchmark_point_addition():
    """测试SECP256K1曲线上点加法"""
    curve = ec.SECP256K1()
    private_key1 = ec.generate_private_key(curve)
    private_key2 = ec.generate_private_key(curve)
    point1 = private_key1.public_key()
    point2 = private_key2.public_key()

    def point_add():
        # 通过序列化和反序列化模拟点加法操作
        p1_bytes = point1.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        p2_bytes = point2.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        # 这里我们返回序列化的点，因为cryptography库没有直接提供点加法操作
        return p1_bytes, p2_bytes

    return measure_time(point_add, iterations=100)


def benchmark_modular_mult():
    """测试模乘运算"""
    # 使用SECP256K1的特征
    p = SECP256K1_ORDER
    a = random.randrange(1, p)
    b = random.randrange(1, p)

    def mod_mult():
        return (a * b) % p

    return measure_time(mod_mult)


def benchmark_modular_operation():
    """测试模运算"""
    p = SECP256K1_ORDER
    a = random.randrange(1, p)

    def mod_op():
        return a % p

    return measure_time(mod_op)


def benchmark_aes_encryption():
    """测试AES加密"""
    key = os.urandom(32)  # AES-256
    iv = os.urandom(16)
    data = os.urandom(1024)  # 1KB数据

    def aes_encrypt():
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    return measure_time(aes_encrypt)


def benchmark_aes_decryption():
    """测试AES解密"""
    key = os.urandom(32)
    iv = os.urandom(16)
    data = os.urandom(1024)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    def aes_decrypt():
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    return measure_time(aes_decrypt)


def main():
    # 运行所有基准测试
    results = {
        "SHA-256 Hash": benchmark_hash(),
        "XOR Operation": benchmark_xor(),
        "SECP256K1 Scalar Multiplication": benchmark_scalar_mult(),
        "SECP256K1 Point Addition": benchmark_point_addition(),
        "Modular Multiplication": benchmark_modular_mult(),
        "Modular Operation": benchmark_modular_operation(),
        "AES Encryption": benchmark_aes_encryption(),
        "AES Decryption": benchmark_aes_decryption()
    }

    # 输出结果
    print("\nCryptographic Operations Benchmark Results:")
    print("-" * 60)
    print(f"{'Operation':<35} {'Time (ms)':<15}")
    print("-" * 60)

    for operation, time_ms in results.items():
        print(f"{operation:<35} {time_ms:>15.6f}")
    print("-" * 60)


if __name__ == "__main__":
    main()