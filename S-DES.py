import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import string


class SDES:
    """S-DES算法实现类"""

    # 置换盒定义
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    LEFT_SHIFT1 = [2, 3, 4, 5, 1]  # 左移1位
    LEFT_SHIFT2 = [3, 4, 5, 1, 2]  # 左移2位
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
    EP_BOX = [4, 1, 2, 3, 2, 3, 4, 1]
    S1_BOX = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 0, 2]
    ]
    S2_BOX = [
        [0, 1, 2, 3],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]
    SP_BOX = [2, 4, 3, 1]

    @staticmethod
    def permute(block, permutation):
        """按置换表对数据块进行置换"""
        return [block[i - 1] for i in permutation]

    @staticmethod
    def left_shift(block, shift_table):
        """按移位表进行左移"""
        return [block[i - 1] for i in shift_table]

    @staticmethod
    def generate_keys(key):
        """生成两个子密钥k1和k2"""
        # 验证密钥长度
        if len(key) != 10:
            raise ValueError("密钥必须是10位二进制数")

        # P10置换
        p10_key = SDES.permute(key, SDES.P10)

        # 分为左右两部分
        left = p10_key[:5]
        right = p10_key[5:]

        # 生成k1
        left1 = SDES.left_shift(left, SDES.LEFT_SHIFT1)
        right1 = SDES.left_shift(right, SDES.LEFT_SHIFT1)
        k1 = SDES.permute(left1 + right1, SDES.P8)

        # 生成k2
        left2 = SDES.left_shift(left1, SDES.LEFT_SHIFT2)
        right2 = SDES.left_shift(right1, SDES.LEFT_SHIFT2)
        k2 = SDES.permute(left2 + right2, SDES.P8)

        return k1, k2

    @staticmethod
    def f_function(right, subkey):
        """轮函数f"""
        # 扩展置换
        expanded = SDES.permute(right, SDES.EP_BOX)

        # 与子密钥异或
        xor_result = [expanded[i] ^ subkey[i] for i in range(8)]

        # S盒替换
        s1_input = xor_result[:4]
        s2_input = xor_result[4:]

        # 计算S1盒输出
        s1_row = s1_input[0] * 2 + s1_input[3]
        s1_col = s1_input[1] * 2 + s1_input[2]
        s1_out = SDES.S1_BOX[s1_row][s1_col]
        s1_bits = [(s1_out >> 1) & 1, s1_out & 1]

        # 计算S2盒输出
        s2_row = s2_input[0] * 2 + s2_input[3]
        s2_col = s2_input[1] * 2 + s2_input[2]
        s2_out = SDES.S2_BOX[s2_row][s2_col]
        s2_bits = [(s2_out >> 1) & 1, s2_out & 1]

        # SP盒置换
        sp_input = s1_bits + s2_bits
        sp_output = SDES.permute(sp_input, SDES.SP_BOX)

        return sp_output

    @staticmethod
    def encrypt(plaintext, key):
        """加密函数"""
        # 验证明文长度
        if len(plaintext) != 8:
            raise ValueError("明文必须是8位二进制数")

        # 生成子密钥
        k1, k2 = SDES.generate_keys(key)

        # 初始置换
        ip_result = SDES.permute(plaintext, SDES.IP)
        left, right = ip_result[:4], ip_result[4:]

        # 第一轮Feistel网络
        f_output = SDES.f_function(right, k1)
        new_left = [left[i] ^ f_output[i] for i in range(4)]
        new_right = right

        # 交换
        left, right = new_right, new_left

        # 第二轮Feistel网络
        f_output = SDES.f_function(right, k2)
        new_left = [left[i] ^ f_output[i] for i in range(4)]
        new_right = right

        # 组合并进行最终置换
        pre_output = new_left + new_right
        ciphertext = SDES.permute(pre_output, SDES.IP_INV)

        return ciphertext

    @staticmethod
    def decrypt(ciphertext, key):
        """解密函数"""
        # 验证密文长度
        if len(ciphertext) != 8:
            raise ValueError("密文必须是8位二进制数")

        # 生成子密钥
        k1, k2 = SDES.generate_keys(key)

        # 初始置换
        ip_result = SDES.permute(ciphertext, SDES.IP)
        left, right = ip_result[:4], ip_result[4:]

        # 第一轮Feistel网络（使用k2）
        f_output = SDES.f_function(right, k2)
        new_left = [left[i] ^ f_output[i] for i in range(4)]
        new_right = right

        # 交换
        left, right = new_right, new_left

        # 第二轮Feistel网络（使用k1）
        f_output = SDES.f_function(right, k1)
        new_left = [left[i] ^ f_output[i] for i in range(4)]
        new_right = right

        # 组合并进行最终置换
        pre_output = new_left + new_right
        plaintext = SDES.permute(pre_output, SDES.IP_INV)

        return plaintext

    @staticmethod
    def str_to_bin_list(s):
        """将ASCII字符串转换为二进制列表的列表（每个字符8位）"""
        result = []
        for char in s:
            # 将字符转换为8位二进制，不足8位前面补0
            bin_str = bin(ord(char))[2:].zfill(8)
            result.append([int(bit) for bit in bin_str])
        return result

    @staticmethod
    def bin_list_to_str(bin_lists):
        """将二进制列表的列表转换为ASCII字符串"""
        result = []
        for bits in bin_lists:
            # 将8位二进制转换为整数，再转换为字符
            bin_str = ''.join(str(bit) for bit in bits)
            result.append(chr(int(bin_str, 2)))
        return ''.join(result)

    @staticmethod
    def encrypt_str(plaintext_str, key):
        """加密ASCII字符串"""
        # 将字符串转换为二进制列表
        bin_blocks = SDES.str_to_bin_list(plaintext_str)
        # 逐个块加密
        encrypted_blocks = [SDES.encrypt(block, key) for block in bin_blocks]
        # 转换回字符串
        return SDES.bin_list_to_str(encrypted_blocks)

    @staticmethod
    def decrypt_str(ciphertext_str, key):
        """解密ASCII字符串"""
        # 将字符串转换为二进制列表
        bin_blocks = SDES.str_to_bin_list(ciphertext_str)
        # 逐个块解密
        decrypted_blocks = [SDES.decrypt(block, key) for block in bin_blocks]
        # 转换回字符串
        return SDES.bin_list_to_str(decrypted_blocks)

    @staticmethod
    def brute_force(plaintext, ciphertext, progress_callback=None):
        """暴力破解密钥"""
        start_time = time.time()
        found_keys = []

        # 遍历所有可能的10位密钥（0-1023）
        for key_int in range(0, 1024):
            # 更新进度
            if progress_callback and key_int % 10 == 0:
                progress = (key_int / 1023) * 100
                progress_callback(progress)

            # 将整数转换为10位二进制列表
            key_bin = [int(bit) for bit in bin(key_int)[2:].zfill(10)]

            # 尝试加密
            try:
                encrypted = SDES.encrypt(plaintext, key_bin)
                if encrypted == ciphertext:
                    found_keys.append((key_int, key_bin))
            except:
                continue

        end_time = time.time()
        elapsed_time = end_time - start_time

        return {
            'keys': found_keys,
            'count': len(found_keys),
            'time': elapsed_time
        }


class SDESGUI:
    """S-DES算法GUI界面"""

    def __init__(self, root):
        self.root = root
        self.root.title("S-DES加密解密工具")
        self.root.geometry("650x500")
        self.root.resizable(True, True)

        # 设置样式
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("SimHei", 10))
        self.style.configure("TButton", font=("SimHei", 10))
        self.style.configure("TEntry", font=("SimHei", 10))

        # 创建标签页
        self.tab_control = ttk.Notebook(root)

        self.tab_basic = ttk.Frame(self.tab_control)
        self.tab_string = ttk.Frame(self.tab_control)
        self.tab_brute = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab_basic, text="基本加密解密")
        self.tab_control.add(self.tab_string, text="字符串加密解密")
        self.tab_control.add(self.tab_brute, text="暴力破解")

        self.tab_control.pack(expand=1, fill="both")

        self.init_basic_tab()
        self.init_string_tab()
        self.init_brute_tab()

        # 破解线程
        self.brute_thread = None
        self.stop_brute = False

    def init_basic_tab(self):
        """初始化基本加密解密标签页"""
        frame = ttk.Frame(self.tab_basic, padding="10")
        frame.pack(fill="both", expand=True)

        # 明文输入
        ttk.Label(frame, text="8位明文 (二进制):").grid(row=0, column=0, sticky="w", pady=5)
        self.plaintext_entry = ttk.Entry(frame, width=30)
        self.plaintext_entry.grid(row=0, column=1, pady=5)
        ttk.Label(frame, text="例如: 01010101").grid(row=0, column=2, sticky="w", pady=5)

        # 密钥输入
        ttk.Label(frame, text="10位密钥 (二进制):").grid(row=1, column=0, sticky="w", pady=5)
        self.key_entry = ttk.Entry(frame, width=30)
        self.key_entry.grid(row=1, column=1, pady=5)
        ttk.Label(frame, text="例如: 1010101010").grid(row=1, column=2, sticky="w", pady=5)

        # 加密按钮
        encrypt_btn = ttk.Button(frame, text="加密", command=self.basic_encrypt)
        encrypt_btn.grid(row=2, column=0, pady=10)

        # 解密按钮
        decrypt_btn = ttk.Button(frame, text="解密", command=self.basic_decrypt)
        decrypt_btn.grid(row=2, column=1, pady=10)

        # 密文输入/输出
        ttk.Label(frame, text="8位密文 (二进制):").grid(row=3, column=0, sticky="w", pady=5)
        self.ciphertext_entry = ttk.Entry(frame, width=30)
        self.ciphertext_entry.grid(row=3, column=1, pady=5)

        # 结果显示
        ttk.Label(frame, text="结果:").grid(row=4, column=0, sticky="w", pady=5)
        self.result_text = tk.Text(frame, height=6, width=40)
        self.result_text.grid(row=4, column=1, columnspan=2, pady=5)
        scroll = ttk.Scrollbar(frame, command=self.result_text.yview)
        scroll.grid(row=4, column=3, sticky="nsew")
        self.result_text.config(yscrollcommand=scroll.set)

    def init_string_tab(self):
        """初始化字符串加密解密标签页"""
        frame = ttk.Frame(self.tab_string, padding="10")
        frame.pack(fill="both", expand=True)

        # 明文输入
        ttk.Label(frame, text="明文 (ASCII字符串):").grid(row=0, column=0, sticky="nw", pady=5)
        self.str_plaintext = tk.Text(frame, height=5, width=40)
        self.str_plaintext.grid(row=0, column=1, pady=5)
        scroll1 = ttk.Scrollbar(frame, command=self.str_plaintext.yview)
        scroll1.grid(row=0, column=2, sticky="nsew")
        self.str_plaintext.config(yscrollcommand=scroll1.set)

        # 密钥输入
        ttk.Label(frame, text="10位密钥 (二进制):").grid(row=1, column=0, sticky="w", pady=5)
        self.str_key_entry = ttk.Entry(frame, width=30)
        self.str_key_entry.grid(row=1, column=1, pady=5)
        ttk.Label(frame, text="例如: 1010101010").grid(row=1, column=2, sticky="w", pady=5)

        # 加密解密按钮
        encrypt_btn = ttk.Button(frame, text="加密", command=self.string_encrypt)
        encrypt_btn.grid(row=2, column=0, pady=10)

        decrypt_btn = ttk.Button(frame, text="解密", command=self.string_decrypt)
        decrypt_btn.grid(row=2, column=1, pady=10)

        # 密文/结果
        ttk.Label(frame, text="结果:").grid(row=3, column=0, sticky="nw", pady=5)
        self.str_result = tk.Text(frame, height=5, width=40)
        self.str_result.grid(row=3, column=1, pady=5)
        scroll2 = ttk.Scrollbar(frame, command=self.str_result.yview)
        scroll2.grid(row=3, column=2, sticky="nsew")
        self.str_result.config(yscrollcommand=scroll2.set)

    def init_brute_tab(self):
        """初始化暴力破解标签页"""
        frame = ttk.Frame(self.tab_brute, padding="10")
        frame.pack(fill="both", expand=True)

        # 明文输入
        ttk.Label(frame, text="明文 (8位二进制):").grid(row=0, column=0, sticky="w", pady=5)
        self.brute_plaintext = ttk.Entry(frame, width=30)
        self.brute_plaintext.grid(row=0, column=1, pady=5)

        # 密文输入
        ttk.Label(frame, text="密文 (8位二进制):").grid(row=1, column=0, sticky="w", pady=5)
        self.brute_ciphertext = ttk.Entry(frame, width=30)
        self.brute_ciphertext.grid(row=1, column=1, pady=5)

        # 进度条
        ttk.Label(frame, text="破解进度:").grid(row=2, column=0, sticky="w", pady=5)
        self.brute_progress = ttk.Progressbar(frame, orient="horizontal", length=200, mode="determinate")
        self.brute_progress.grid(row=2, column=1, pady=5)

        # 按钮
        self.start_brute_btn = ttk.Button(frame, text="开始破解", command=self.start_brute_force)
        self.start_brute_btn.grid(row=3, column=0, pady=10)

        self.stop_brute_btn = ttk.Button(frame, text="停止破解", command=self.stop_brute_force, state="disabled")
        self.stop_brute_btn.grid(row=3, column=1, pady=10)

        # 结果
        ttk.Label(frame, text="破解结果:").grid(row=4, column=0, sticky="nw", pady=5)
        self.brute_result = tk.Text(frame, height=8, width=40)
        self.brute_result.grid(row=4, column=1, pady=5)
        scroll = ttk.Scrollbar(frame, command=self.brute_result.yview)
        scroll.grid(row=4, column=2, sticky="nsew")
        self.brute_result.config(yscrollcommand=scroll.set)

    def validate_binary(self, text, length):
        """验证二进制字符串"""
        if len(text) != length:
            return False, f"长度必须为{length}位"
        for c in text:
            if c not in ['0', '1']:
                return False, "必须只包含0和1"
        return True, "验证通过"

    def basic_encrypt(self):
        """基本加密功能"""
        try:
            plaintext = self.plaintext_entry.get().strip()
            key = self.key_entry.get().strip()

            # 验证输入
            valid, msg = self.validate_binary(plaintext, 8)
            if not valid:
                messagebox.showerror("输入错误", f"明文{msg}")
                return

            valid, msg = self.validate_binary(key, 10)
            if not valid:
                messagebox.showerror("输入错误", f"密钥{msg}")
                return

            # 转换为二进制列表
            plaintext_bin = [int(bit) for bit in plaintext]
            key_bin = [int(bit) for bit in key]

            # 加密
            ciphertext = SDES.encrypt(plaintext_bin, key_bin)
            ciphertext_str = ''.join(str(bit) for bit in ciphertext)

            # 显示结果
            self.ciphertext_entry.delete(0, tk.END)
            self.ciphertext_entry.insert(0, ciphertext_str)

            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"加密成功!\n")
            self.result_text.insert(tk.END, f"明文: {plaintext}\n")
            self.result_text.insert(tk.END, f"密钥: {key}\n")
            self.result_text.insert(tk.END, f"密文: {ciphertext_str}")

        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def basic_decrypt(self):
        """基本解密功能"""
        try:
            ciphertext = self.ciphertext_entry.get().strip()
            key = self.key_entry.get().strip()

            # 验证输入
            valid, msg = self.validate_binary(ciphertext, 8)
            if not valid:
                messagebox.showerror("输入错误", f"密文{msg}")
                return

            valid, msg = self.validate_binary(key, 10)
            if not valid:
                messagebox.showerror("输入错误", f"密钥{msg}")
                return

            # 转换为二进制列表
            ciphertext_bin = [int(bit) for bit in ciphertext]
            key_bin = [int(bit) for bit in key]

            # 解密
            plaintext = SDES.decrypt(ciphertext_bin, key_bin)
            plaintext_str = ''.join(str(bit) for bit in plaintext)

            # 显示结果
            self.plaintext_entry.delete(0, tk.END)
            self.plaintext_entry.insert(0, plaintext_str)

            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"解密成功!\n")
            self.result_text.insert(tk.END, f"密文: {ciphertext}\n")
            self.result_text.insert(tk.END, f"密钥: {key}\n")
            self.result_text.insert(tk.END, f"明文: {plaintext_str}")

        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def string_encrypt(self):
        """字符串加密功能"""
        try:
            plaintext = self.str_plaintext.get(1.0, tk.END).strip()
            key = self.str_key_entry.get().strip()

            # 验证密钥
            valid, msg = self.validate_binary(key, 10)
            if not valid:
                messagebox.showerror("输入错误", f"密钥{msg}")
                return

            # 转换密钥为二进制列表
            key_bin = [int(bit) for bit in key]

            # 加密
            ciphertext = SDES.encrypt_str(plaintext, key_bin)

            # 显示结果
            self.str_result.delete(1.0, tk.END)
            self.str_result.insert(tk.END, ciphertext)

        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def string_decrypt(self):
        """字符串解密功能"""
        try:
            ciphertext = self.str_result.get(1.0, tk.END).strip()
            key = self.str_key_entry.get().strip()

            # 验证密钥
            valid, msg = self.validate_binary(key, 10)
            if not valid:
                messagebox.showerror("输入错误", f"密钥{msg}")
                return

            # 转换密钥为二进制列表
            key_bin = [int(bit) for bit in key]

            # 解密
            plaintext = SDES.decrypt_str(ciphertext, key_bin)

            # 显示结果
            self.str_plaintext.delete(1.0, tk.END)
            self.str_plaintext.insert(tk.END, plaintext)

        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def update_brute_progress(self, value):
        """更新破解进度条"""
        self.brute_progress["value"] = value
        self.root.update_idletasks()

    def brute_force_worker(self):
        """暴力破解工作线程"""
        try:
            plaintext_str = self.brute_plaintext.get().strip()
            ciphertext_str = self.brute_ciphertext.get().strip()

            # 验证输入
            valid, msg = self.validate_binary(plaintext_str, 8)
            if not valid:
                messagebox.showerror("输入错误", f"明文{msg}")
                self.reset_brute_ui()
                return

            valid, msg = self.validate_binary(ciphertext_str, 8)
            if not valid:
                messagebox.showerror("输入错误", f"密文{msg}")
                self.reset_brute_ui()
                return

            # 转换为二进制列表
            plaintext = [int(bit) for bit in plaintext_str]
            ciphertext = [int(bit) for bit in ciphertext_str]

            # 执行暴力破解
            result = SDES.brute_force(plaintext, ciphertext, self.update_brute_progress)

            # 显示结果
            self.brute_result.delete(1.0, tk.END)
            self.brute_result.insert(tk.END, f"破解完成! 耗时: {result['time']:.4f}秒\n")
            self.brute_result.insert(tk.END, f"找到{result['count']}个可能的密钥:\n\n")

            for i, (key_int, key_bin) in enumerate(result['keys'], 1):
                key_str = ''.join(str(bit) for bit in key_bin)
                self.brute_result.insert(tk.END, f"密钥{i}: {key_str} (十进制: {key_int})\n")

            # 分析结果
            if result['count'] > 1:
                self.brute_result.insert(tk.END, "\n注意: 存在多个密钥可以得到相同的明密文对，")
                self.brute_result.insert(tk.END, "这表明S-DES算法存在密钥碰撞现象。")

        except Exception as e:
            self.brute_result.delete(1.0, tk.END)
            self.brute_result.insert(tk.END, f"破解出错: {str(e)}")
        finally:
            self.reset_brute_ui()

    def start_brute_force(self):
        """开始暴力破解"""
        self.brute_result.delete(1.0, tk.END)
        self.brute_result.insert(tk.END, "正在破解，请稍候...\n")
        self.brute_progress["value"] = 0

        self.start_brute_btn.config(state="disabled")
        self.stop_brute_btn.config(state="normal")

        # 启动破解线程
        self.brute_thread = threading.Thread(target=self.brute_force_worker)
        self.brute_thread.daemon = True
        self.brute_thread.start()

    def stop_brute_force(self):
        """停止暴力破解"""
        if self.brute_thread and self.brute_thread.is_alive():
            self.stop_brute = True
            self.brute_result.insert(tk.END, "\n正在停止破解...\n")

    def reset_brute_ui(self):
        """重置破解界面状态"""
        self.start_brute_btn.config(state="normal")
        self.stop_brute_btn.config(state="disabled")
        self.stop_brute = False


if __name__ == "__main__":
    root = tk.Tk()
    app = SDESGUI(root)
    root.mainloop()