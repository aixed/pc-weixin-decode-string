import json
import ida_segment
import ida_bytes
import os

def process_json_and_patch(json_path):
    """
    读取 JSON 文件，定位地址，检查是否在 rdata 段，
    如果是则将 real_name 写入该地址
    """
    if not os.path.exists(json_path):
        print(f"[!] 文件不存在: {json_path}")
        return

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    modified_count = 0
    skipped_count = 0
    error_count = 0

    for item in data:
        target_addr_str = item.get('target_addr', '')
        real_name = item.get('real_name', '')

        if not target_addr_str or not real_name:
            print(f"[!] 跳过: 缺少 target_addr 或 real_name")
            skipped_count += 1
            continue

        try:
            target_addr = int(target_addr_str, 16)
        except ValueError:
            print(f"[!] 地址格式错误: {target_addr_str}")
            error_count += 1
            continue

        seg = ida_segment.getseg(target_addr)
        if seg is None:
            print(f"[!] 无法获取地址 {target_addr_str} 的段信息")
            error_count += 1
            continue

        seg_name = ida_segment.get_segm_name(seg)
        print(f"[*] 地址: {target_addr_str}, 段: {seg_name}, 名称: {real_name}")

        if seg_name != '.rdata':
            print(f"    [!] 跳过: 不在 rdata 段")
            skipped_count += 1
            continue

        name_bytes = real_name.encode('utf-8') + b'\x00'
        original_bytes = ida_bytes.get_bytes(target_addr, len(name_bytes))

        if original_bytes is None:
            print(f"[!] 无法读取地址 {target_addr_str} 的数据")
            error_count += 1
            continue

        try:
            ida_bytes.patch_bytes(target_addr, name_bytes)
            print(f"    [+] 已修改: {real_name}")
            modified_count += 1
        except Exception as e:
            print(f"[!] 写入失败: {e}")
            error_count += 1

    print(f"\n[+] 完成!")
    print(f"    修改: {modified_count}")
    print(f"    跳过: {skipped_count}")
    print(f"    错误: {error_count}")

if __name__ == '__main__':
    json_file = r"C:\Users\Administrator\Desktop\any\result_4.1.5.30.json"
    process_json_and_patch(json_file)
