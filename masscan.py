# -*- coding: utf-8 -*-

import os

def convert_masscan_output():
    """
    一个交互式脚本，用于将 Masscan 的默认 TXT 输出文件转换为 'ip:port' 格式列表。
    """
    print("--- Masscan 结果转换脚本 ---")
    print("本脚本将 'Discovered open port 80/tcp on 192.168.1.1' 格式的行转换为 '192.168.1.1:80'")

    # 1. 获取用户输入的源文件路径
    while True:
        input_file_path = input("\n请输入 Masscan 结果文件名 (例如 results.txt): ").strip()
        if os.path.exists(input_file_path):
            break
        else:
            print(f"错误: 文件 '{input_file_path}' 不存在，请检查文件名和路径是否正确。")

    # 2. 获取用户指定的输出文件路径
    default_output_name = f"converted_{os.path.basename(input_file_path)}"
    output_file_path = input(f"请输入转换后保存的文件名 (默认: {default_output_name}): ").strip()
    if not output_file_path:
        output_file_path = default_output_name

    # 3. 开始转换
    converted_count = 0
    total_lines = 0

    print(f"\n正在读取文件: {input_file_path}")
    print(f"准备写入文件: {output_file_path}")

    try:
        # 使用 'with' 语句确保文件能被正确关闭
        with open(input_file_path, 'r', encoding='utf-8') as infile, \
             open(output_file_path, 'w', encoding='utf-8') as outfile:

            for line in infile:
                total_lines += 1
                line = line.strip()

                # 检查是否是 masscan 的标准发现行
                if line.startswith("Discovered open port"):
                    try:
                        # 分割字符串来提取所需信息
                        parts = line.split()
                        
                        # parts 列表应该是 ['Discovered', 'open', 'port', '80/tcp', 'on', '192.168.1.1']
                        # 检查列表长度是否足够，防止索引错误
                        if len(parts) >= 6:
                            port_str = parts[3].split('/')[0] # 从 '80/tcp' 中提取 '80'
                            ip_addr = parts[5]
                            
                            # 格式化并写入文件
                            formatted_line = f"{ip_addr}:{port_str}\n"
                            outfile.write(formatted_line)
                            converted_count += 1
                        else:
                            # 如果某行以 "Discovered open port" 开头但格式不完整，则打印提示
                            print(f"警告: 跳过格式异常的行: {line}")

                    except IndexError:
                        # 如果分割或索引操作失败，则跳过此行
                        print(f"警告: 跳过格式错误的行: {line}")
                        continue
    
    except Exception as e:
        print(f"\n处理文件时发生未知错误: {e}")
        return

    print("\n--- 转换完成 ---")
    print(f"总共读取行数: {total_lines}")
    print(f"成功转换记录: {converted_count}")
    print(f"结果已保存到文件: {output_file_path}")


if __name__ == "__main__":
    convert_masscan_output()
