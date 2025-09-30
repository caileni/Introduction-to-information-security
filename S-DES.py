class S_DES:
    def __init__(self):
        # 初始置换表IP
        self.IP = [2, 6, 3, 1, 4, 5, 7, 8]
        # 初始逆置换表IP_inv
        self.IP_inv = [4, 1, 3, 5, 6, 2, 7, 8]
        # 扩展置换IP_inv换表EP
        self.EP = [4, 1, 2, 3, 2, 3, 4, 1]
        # P4置换表
        self.P4 = [2, 4, 3, 1]
        # P10置换表
        self.P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        # P8置换表
        self.P8 = [6, 3, 7, 4, 8, 5, 10, 9]
        # S盒1
        self.S1 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 3, 2]
        ]
        # S盒2
        self.S2 = [
            [0, 1, 2, 3],
            [2, 0, 1, 3],
            [3, 0, 1, 0],
            [2, 1, 0, 3]
        ]

    def permute(self, block, table):
        """根据置换表对数据进行置换"""
        return [block[i - 1] for i in table]

    def left_shift(self, bits, n=1):
        """对数据进行左移操作"""
        return bits[n:] + bits[:n]

    def generate_keys(self, key):
        """生成两个子密钥K1和K2"""
        if len(key) != 10:
            raise ValueError("密钥必须是10位二进制数")

        # P10置换
        key_p10 = self.permute(key, self.P10)

        # 分为左右两部分
        left = key_p10[:5]
        right = key_p10[5:]

        # 生成K1
        left1 = self.left_shift(left)
        right1 = self.left_shift(right)
        key1 = self.permute(left1 + right1, self.P8)

        # 生成K2（左移2位）
        left2 = self.left_shift(left1, 2)
        right2 = self.left_shift(right1, 2)
        key2 = self.permute(left2 + right2, self.P8)

        return key1, key2

    def f_function(self, right, subkey):
        """F函数：扩展置换、异或、S盒替换、P4置换"""
        # 扩展置换
        expanded = self.permute(right, self.EP)

        # 与子密钥异或
        xor_result = [expanded[i] ^ subkey[i] for i in range(8)]

        # S盒替换
        left_s = xor_result[:4]
        right_s = xor_result[4:]

        # 计算S1盒的行和列
        row_s1 = left_s[0] * 2 + left_s[3]
        col_s1 = left_s[1] * 2 + left_s[2]
        s1_out = self.bin_to_list(bin(self.S1[row_s1][col_s1])[2:].zfill(2))

        # 计算S2盒的行和列
        row_s2 = right_s[0] * 2 + right_s[3]
        col_s2 = right_s[1] * 2 + right_s[2]
        s2_out = self.bin_to_list(bin(self.S2[row_s2][col_s2])[2:].zfill(2))

        # P4置换
        return self.permute(s1_out + s2_out, self.P4)

    def encrypt(self, plaintext, key):
        """加密函数"""
        if len(plaintext) != 8:
            raise ValueError("明文必须是8位二进制数")

        # 生成子密钥
        k1, k2 = self.generate_keys(key)

        # 初始置换IP
        ip_result = self.permute(plaintext, self.IP)
        left, right = ip_result[:4], ip_result[4:]

        # 第一轮迭代
        f_output = self.f_function(right, k1)
        new_left = [left[i] ^ f_output[i] for i in range(4)]
        new_right = right

        # 交换左右部分
        left, right = new_right, new_left

        # 第二轮迭代
        f_output = self.f_function(right, k2)
        new_left = [left[i] ^ f_output[i] for i in range(4)]
        new_right = right

        # 组合并进行初始逆置换
        pre_output = new_left + new_right
        ciphertext = self.permute(pre_output, self.IP_inv)

        return ciphertext

    def decrypt(self, ciphertext, key):
        """解密函数（与加密类似，但子密钥使用顺序相反）"""
        if len(ciphertext) != 8:
            raise ValueError("密文必须是8位二进制数")

        k1, k2 = self.generate_keys(key)

        # 初始置换IP
        ip_result = self.permute(ciphertext, self.IP)
        left, right = ip_result[:4], ip_result[4:]

        # 第一轮迭代（使用K2）
        f_output = self.f_function(right, k2)
        new_left = [left[i] ^ f_output[i] for i in range(4)]
        new_right = right

        # 交换左右部分
        left, right = new_right, new_left

        # 第二轮迭代（使用K1）
        f_output = self.f_function(right, k1)
        new_left = [left[i] ^ f_output[i] for i in range(4)]
        new_right = right

        # 组合并进行初始逆置换
        pre_output = new_left + new_right
        plaintext = self.permute(pre_output, self.IP_inv)

        return plaintext

    @staticmethod
    def bin_to_list(bin_str):
        """将二进制字符串转换为整数列表"""
        return [int(bit) for bit in bin_str]

    @staticmethod
    def list_to_bin(bits_list):
        """将整数列表转换为二进制字符串"""
        return ''.join(str(bit) for bit in bits_list)

    def brute_force_attack(self, plaintext, ciphertext):
        """
        暴力破解S-DES密钥
        参数:
            plaintext: 明文（8位二进制列表）
            ciphertext: 密文（8位二进制列表）
        返回:
            找到的密钥列表（10位二进制字符串）
        """
        found_keys = []
        # 遍历所有可能的10位密钥（2^10 = 1024种可能）
        for key_int in range(0, 1024):
            # 转换为10位二进制字符串
            key_str = bin(key_int)[2:].zfill(10)
            key = self.bin_to_list(key_str)

            # 尝试用当前密钥加密明文
            try:
                encrypted = self.encrypt(plaintext, key)
                if encrypted == ciphertext:
                    found_keys.append(key_str)
            except:
                continue

        return found_keys

    def closed_test(self, test_count=100):
        """
        封闭式测试：随机生成密钥和明文，验证加密解密的一致性
        参数:
            test_count: 测试次数
        返回:
            测试结果（是否全部通过）
        """
        import random
        pass_count = 0

        print(f"开始封闭式测试，共进行{test_count}次测试...")

        for i in range(test_count):
            # 随机生成10位密钥
            key = [random.randint(0, 1) for _ in range(10)]
            # 随机生成8位明文
            plaintext = [random.randint(0, 1) for _ in range(8)]

            # 加密
            ciphertext = self.encrypt(plaintext, key)
            # 解密
            decrypted = self.decrypt(ciphertext, key)

            # 验证
            if decrypted == plaintext:
                pass_count += 1
            else:
                print(f"测试失败 #{i + 1}")
                print(f"密钥: {self.list_to_bin(key)}")
                print(f"明文: {self.list_to_bin(plaintext)}")
                print(f"密文: {self.list_to_bin(ciphertext)}")
                print(f"解密结果: {self.list_to_bin(decrypted)}")

        print(f"测试完成，共{test_count}次，通过{pass_count}次")
        return pass_count == test_count


# 测试代码
if __name__ == "__main__":
    sdes = S_DES()

    # 1. 封闭式测试
    print("=== 封闭式测试 ===")
    sdes.closed_test(100)  # 进行100次随机测试

    # 2. 暴力破解演示
    print("\n=== 暴力破解演示 ===")
    # 已知明文和密文对
    test_key = "1010000010"  # 测试用密钥
    test_plaintext = "01110010"  # 测试用明文

    # 转换为列表格式
    key_list = sdes.bin_to_list(test_key)
    plaintext_list = sdes.bin_to_list(test_plaintext)

    # 加密得到密文
    ciphertext_list = sdes.encrypt(plaintext_list, key_list)
    ciphertext_str = sdes.list_to_bin(ciphertext_list)

    print(f"已知明文: {test_plaintext}")
    print(f"已知密文: {ciphertext_str}")
    print("正在进行暴力破解...")

    # 执行暴力破解
    found_keys = sdes.brute_force_attack(plaintext_list, ciphertext_list)

    print(f"找到的可能密钥({len(found_keys)}个): {found_keys}")
    print(f"原始密钥: {test_key}")
    print(f"破解验证: {'成功' if test_key in found_keys else '失败'}")

    # 3. 组间测试工具
    print("\n=== 组间测试工具 ===")
    while True:
        print("\n请选择操作:")
        print("1. 加密数据")
        print("2. 解密数据")
        print("3. 对已知明文密文对进行暴力破解")
        print("4. 退出")

        choice = input("请输入选择(1-4): ")

        if choice == '1':
            key_str = input("请输入10位二进制密钥: ")
            plaintext_str = input("请输入8位二进制明文: ")
            if len(key_str) != 10 or not all(c in '01' for c in key_str):
                print("错误：密钥必须是10位二进制数")
                continue
            if len(plaintext_str) != 8 or not all(c in '01' for c in plaintext_str):
                print("错误：明文必须是8位二进制数")
                continue

            key = sdes.bin_to_list(key_str)
            plaintext = sdes.bin_to_list(plaintext_str)
            ciphertext = sdes.encrypt(plaintext, key)
            print(f"加密结果: {sdes.list_to_bin(ciphertext)}")

        elif choice == '2':
            key_str = input("请输入10位二进制密钥: ")
            ciphertext_str = input("请输入8位二进制密文: ")
            if len(key_str) != 10 or not all(c in '01' for c in key_str):
                print("错误：密钥必须是10位二进制数")
                continue
            if len(ciphertext_str) != 8 or not all(c in '01' for c in ciphertext_str):
                print("错误：密文必须是8位二进制数")
                continue

            key = sdes.bin_to_list(key_str)
            ciphertext = sdes.bin_to_list(ciphertext_str)
            plaintext = sdes.decrypt(ciphertext, key)
            print(f"解密结果: {sdes.list_to_bin(plaintext)}")

        elif choice == '3':
            plaintext_str = input("请输入已知8位二进制明文: ")
            ciphertext_str = input("请输入对应8位二进制密文: ")
            if len(plaintext_str) != 8 or not all(c in '01' for c in plaintext_str):
                print("错误：明文必须是8位二进制数")
                continue
            if len(ciphertext_str) != 8 or not all(c in '01' for c in ciphertext_str):
                print("错误：密文必须是8位二进制数")
                continue

            plaintext = sdes.bin_to_list(plaintext_str)
            ciphertext = sdes.bin_to_list(ciphertext_str)
            print("正在暴力破解，请稍候...")
            found_keys = sdes.brute_force_attack(plaintext, ciphertext)
            print(f"找到的可能密钥({len(found_keys)}个): {found_keys}")

        elif choice == '4':
            print("退出程序")
            break

        else:
            print("无效选择，请重新输入")