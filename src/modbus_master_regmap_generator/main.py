import pandas as pd
import tkinter as tk
from tkinter import filedialog
import os
import textwrap

MODBUS_SLAVE_ADDR = 0x01  # スレーブアドレス定義（任意に変更可）

# 1レジスタ = 2バイト前提で、型に応じたレジスタ数を計算（未使用）（g_reg_table の size を参照）
def get_register_count(entry_type: str, length: int) -> int:
    if "UINT16" in entry_type:
        return length
    elif "UINT32" in entry_type or "FLOAT" in entry_type:
        return length * 2
    else:
        return length  # fallback

def sanitize_var_name(var_name: str) -> str:
    return str(var_name).replace(".", "_").strip()

def write_modbus_reply_handler_master_c(out_dir: str, entries: list):
    c_lines = [
        '#include "modbus_reply_handler_master.h"',
        '#include "modbus_reg_map_master.h"',
        '#include "modbus_sender_gen.h"',  # 追加されたgetter用
        '#include <string.h>',
        '#include <stdint.h>',
        '',
        '#define MODBUS_FUNC_READ_HOLDING_REGS  (0x03U)',
        '#define MODBUS_FUNC_WRITE_MULTIPLE_REGS (0x10U)',
        '#define MODBUS_MIN_FRAME_LENGTH        (5U + 2U)',  # func + addr + bytecount + CRC
        '',
        'static int modbus_validate_crc(const uint8_t* frame, uint16_t length);',
        'static int is_float_equal(float a, float b);',
        'static int modbus_parse_and_store(const uint8_t *rx_buf, uint16_t len);',
        '',
        'int modbus_reply_handler(const uint8_t *rx_buf, uint16_t len)',
        '{',
        '    if ((rx_buf == (const uint8_t *)0) || (len < 2U)) return -1;',
        '    uint8_t func_code = rx_buf[1];',
        '    switch (func_code)',
        '    {',
        '        case MODBUS_FUNC_READ_HOLDING_REGS:',
        '            return modbus_parse_and_store(rx_buf, len);',
        '        case MODBUS_FUNC_WRITE_MULTIPLE_REGS:',
        '            return modbus_validate_crc(rx_buf, len) ? 0 : -1;',
        '        default:',
        '            return -1;',
        '    }',
        '}',
        '',
        'int modbus_parse_and_store(const uint8_t *rx_buf, uint16_t len)',
        '{',
        '    if ((rx_buf == (const uint8_t *)0) || (len < MODBUS_MIN_FRAME_LENGTH)) return -1;',
        '    if (!modbus_validate_crc(rx_buf, len)) return -1;',
        '    if (rx_buf[1] != MODBUS_FUNC_READ_HOLDING_REGS) return -1;',
        '',
        '    uint8_t byte_count = rx_buf[2];',
        '    if (len < (uint16_t)(3U + byte_count + 2U)) return -1;',
        '    const uint8_t *data = &rx_buf[3];',
        '',
        '    uint16_t start_addr = modbus_sender_get_last_read_addr();',
        '    uint16_t num_regs   = modbus_sender_get_last_read_regs();',
        '    uint16_t end_addr   = (uint16_t)(start_addr + num_regs);',
        '',
        '    for (uint16_t i = 0; i < g_reg_table_master_size; ++i) {',
        '        const reg_table_master_entry_t *entry = &g_reg_table_master[i];',
        '        if ((entry->modbus_addr < start_addr) || (entry->modbus_addr >= end_addr)) continue;',
        '',
        '        uint16_t addr_diff = (uint16_t)(entry->modbus_addr - start_addr);',
        '        uint16_t offset = (uint16_t)(addr_diff * 2U);',        
        '        const uint8_t *src = &data[offset];',
        '        void *dst = entry->ram_ptr;',
        '',
        '        switch (entry->type) {',
        '            case REG_TYPE_MASTER_UINT16: {',
        '                if ((offset + 2U) > byte_count) return -1;',
        '                uint16_t incoming = (uint16_t)(((uint16_t)src[0] << 8U) | (uint16_t)src[1]);',
        '                uint16_t current = *((uint16_t *)dst);',
        '                uint16_t min = *((uint16_t *)(entry->min_value));',
        '                uint16_t max = *((uint16_t *)(entry->max_value));',
        '                if ((incoming < min) || (incoming > max)) return -1;',
        '                if (incoming != current) *((uint16_t *)dst) = incoming;',
        '                break;',
        '            }',
        '            case REG_TYPE_MASTER_UINT32: {',
        '                if ((offset + 4U) > byte_count) return -1;',
        '                uint32_t incoming = ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) | ((uint32_t)src[2] << 8) | src[3];',
        '                uint32_t current = *((uint32_t *)dst);',
        '                uint32_t min = *((uint32_t *)(entry->min_value));',
        '                uint32_t max = *((uint32_t *)(entry->max_value));',
        '                if ((incoming < min) || (incoming > max)) return -1;',
        '                if (incoming != current) *((uint32_t *)dst) = incoming;',
        '                break;',
        '            }',
        '            case REG_TYPE_MASTER_FLOAT: {',
        '                if ((offset + 4U) > byte_count) return -1;',
        '                union { uint32_t u; float f; } conv;',
        '                conv.u = ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) | ((uint32_t)src[2] << 8) | src[3];',
        '                float incoming = conv.f;',
        '                float current = *((float *)dst);',
        '                float min = *((float *)(entry->min_value));',
        '                float max = *((float *)(entry->max_value));',
        '                if ((incoming < min) || (incoming > max)) return -1;',
        '                if (!is_float_equal(incoming, current)) *((float *)dst) = incoming;',
        '                break;',
        '            }',
        '            default:',
        '                break;',
        '        }',
        '    }',
        '    return 0;',
        '}',
        '',
        'static int is_float_equal(float a, float b)',
        '{',
        '    float diff = a - b;',
        '    return (diff < 1.0e-6f) && (diff > -1.0e-6f);',
        '}',
        '',
        'static int modbus_validate_crc(const uint8_t* frame, uint16_t length)',
        '{',
        '    uint16_t crc = 0xFFFFU;',
        '    for (uint16_t i = 0; i < (uint16_t)(length - 2U); ++i) {',
        '        uint16_t byte = (uint16_t)frame[i];',
        '        crc ^= byte;',
        '        for (uint8_t j = 0; j < 8U; ++j) {',
        '            if ((crc & 0x0001U) != 0U)',
        '                crc = (uint16_t)((crc >> 1U) ^ 0xA001U);',
        '            else',
        '                crc = (uint16_t)(crc >> 1U);',
        '        }',
        '    }',
        '    uint16_t recv_crc = (uint16_t)(((uint16_t)frame[length - 1U] << 8U) | frame[length - 2U]);',
        '    return (crc == recv_crc);',
        '}'
    ]

    with open(os.path.join(out_dir, "modbus_reply_handler_master.c"), "w", encoding="utf-8") as f:
        f.write("\n".join(c_lines))


def write_modbus_reply_handler_master_h(out_dir: str):
    h_lines = [
        "#ifndef MODBUS_PARSER_STORE_MASTER_H",
        "#define MODBUS_PARSER_STORE_MASTER_H",
        "",
        "#include <stdint.h>",
        "",
        "int modbus_reply_handler(const uint8_t *rx_buf, uint16_t len);",        
        "",
        "#endif"
    ]

    with open(os.path.join(out_dir, "modbus_reply_handler_master.h"), "w", encoding="utf-8") as f:
        f.write("\n".join(h_lines))

def write_modbus_reg_edge_master_c(out_dir, entries):
    c_lines = [
        '#include "modbus_reg_access_master.h"',
        '#include "modbus_reg_idx_master.h"',
        '#include "modbus_reg_edge_master.h"',
        '',
    ]

    has_float = any("FLOAT" in entry["type"] for entry in entries)
    if has_float:
        c_lines.extend([
        '',    
        '#define FLOAT_EPSILON (1.0e-6f)',
        '',
        'static int is_float_equal(float a, float b)',
        '{',
        '    float diff = a - b;',
        '    return (diff < FLOAT_EPSILON) && (diff > -FLOAT_EPSILON);',
        '}',
        '',
        ])
    c_lines.extend([
        '/* Edge detection functions */'
    ])

    for entry in entries:
        name = entry["name"]
        entry_type = entry["type"]
        is_array = entry["length"] > 1
        length = entry["length"]

        if entry_type == "REG_TYPE_MASTER_FLOAT" and not is_array:
            c_lines.extend([
                f"int detect_{name}_changed(void)",
                "{",
                f"    static float prev;",
                f"    float curr = get_{name}();",
                "    if (!is_float_equal(prev, curr))",
                "    {",
                "        prev = curr;",
                "        return 1;",
                "    }",
                "    prev = curr;",
                "    return 0;",
                "}"
            ])

        elif entry_type in ("REG_TYPE_MASTER_UINT16", "REG_TYPE_MASTER_UINT32") and not is_array:
            for kind, cond in [
                ("rising", "((prev & bit_mask) == 0U) && ((curr & bit_mask) != 0U)"),
                ("falling", "((prev & bit_mask) != 0U) && ((curr & bit_mask) == 0U)"),
                ("toggled", "((prev ^ curr) & bit_mask) != 0U")
            ]:
                c_lines.extend([
                    f"int detect_{name}_{kind}(uint16_t bit_mask)",
                    "{",
                    f"    static uint16_t prev;  // assuming uint16_t always here",
                    f"    uint16_t curr = get_{name}();",
                    f"    if ({cond})",
                    "    {",
                    "        prev = curr;",
                    "        return 1;",
                    "    }",
                    "    prev = curr;",
                    "    return 0;",
                    "}"
                ])

        elif entry_type == "REG_TYPE_MASTER_FLOAT_ARRAY":
            c_lines.extend([
                f"int detect_{name}_changed(uint16_t index)",
                "{",
                f"    static float prev[{length}];",
                "    float curr;",
                f"    if (index >= {length}U) return 0;",
                f"    curr = get_{name}(index);",
                f"    if (!is_float_equal(prev[index], curr))",
                "    {",
                "        prev[index] = curr;",
                "        return 1;",
                "    }",
                "    prev[index] = curr;",
                "    return 0;",
                "}"
            ])

            c_lines.extend([
                f"int detect_{name}_any_changed(void)",
                "{",
                f"    static float prev[{length}];",
                "    float curr;",
                "    uint16_t i;",
                f"    for (i = 0; i < {length}; ++i)",
                "    {",
                f"        curr = get_{name}(i);",
                f"        if (!is_float_equal(prev[i], curr))",
                "        {",
                "            prev[i] = curr;",
                "            return 1;",
                "        }",
                "        prev[i] = curr;",
                "    }",
                "    return 0;",
                "}"
            ])

        elif entry_type in ("REG_TYPE_MASTER_UINT16_ARRAY", "REG_TYPE_MASTER_UINT32_ARRAY"):
            for kind, cond in [
                ("rising", "((prev[index] & bit_mask) == 0U) && ((curr & bit_mask) != 0U)"),
                ("falling", "((prev[index] & bit_mask) != 0U) && ((curr & bit_mask) == 0U)"),
                ("toggled", "((prev[index] ^ curr) & bit_mask) != 0U")
            ]:
                c_lines.extend([
                    f"int detect_{name}_{kind}_edge(uint16_t index, uint16_t bit_mask)",
                    "{",
                    f"    static uint16_t prev[{length}];",
                    f"    uint16_t curr;",
                    f"    if (index >= {length}U) return 0;",
                    f"    curr = get_{name}(index);",
                    f"    if ({cond})",
                    "    {",
                    "        prev[index] = curr;",
                    "        return 1;",
                    "    }",
                    "    prev[index] = curr;",
                    "    return 0;",
                    "}"
                ])

            c_lines.extend([
                f"int detect_{name}_any_changed(void)",
                "{",
                f"    static uint16_t prev[{length}];",
                f"    uint16_t curr;",
                "    uint16_t i;",
                f"    for (i = 0; i < {length}; ++i)",
                "    {",
                f"        curr = get_{name}(i);",
                "        if (curr != prev[i])",
                "        {",
                "            prev[i] = curr;",
                "            return 1;",
                "        }",
                "        prev[i] = curr;",
                "    }",
                "    return 0;",
                "}"
            ])

    # init 関数
    c_lines.append("")
    c_lines.append("void modbus_reg_edge_master_init(void)")
    c_lines.append("{")

    # 🔽 配列エントリが存在するかチェック
    has_array_entries = any(entry["length"] > 1 for entry in entries)

    if has_array_entries:    
        c_lines.append("    uint16_t i = 0;")
    
    c_lines.append("")    

    for entry in entries:
        name = entry["name"]
        entry_type = entry["type"]
        is_array = entry["length"] > 1
        length = entry["length"]

        if entry_type == "REG_TYPE_MASTER_FLOAT" and not is_array:
            c_lines.append(f"    (void)detect_{name}_changed();")
        elif entry_type in ("REG_TYPE_MASTER_UINT16", "REG_TYPE_MASTER_UINT32") and not is_array:
            for kind in ("rising", "falling", "toggled"):
                c_lines.append(f"    (void)detect_{name}_{kind}(0xFFFF);")
        elif entry_type == "REG_TYPE_MASTER_FLOAT_ARRAY":
            c_lines.append(f"    for (i = 0; i < {length}U; ++i) (void)detect_{name}_changed(i);")
            c_lines.append(f"    (void)detect_{name}_any_changed();")
        elif entry_type in ("REG_TYPE_MASTER_UINT16_ARRAY", "REG_TYPE_MASTER_UINT32_ARRAY"):
            for kind in ("rising", "falling", "toggled"):
                c_lines.append(f"    for (i = 0; i < {length}U; ++i) (void)detect_{name}_{kind}_edge(i, 0xFFFF);")
            c_lines.append(f"    (void)detect_{name}_any_changed();")
    c_lines.append("}")

    with open(os.path.join(out_dir, "modbus_reg_edge_master.c"), "w", encoding="utf-8") as f:
        f.write("\n".join(c_lines))

def write_modbus_reg_edge_master_h(out_dir, entries):
    h_lines = [
        "#ifndef MODBUS_REG_EDGE_MASTER_H",
        "#define MODBUS_REG_EDGE_MASTER_H",
        "",
        "#include <stdint.h>",
        "",
        "void modbus_reg_edge_master_init(void);"
    ]

    for entry in entries:
        name = entry["name"]
        entry_type = entry["type"]
        is_array = entry["length"] > 1

        if entry_type == "REG_TYPE_MASTER_FLOAT" and not is_array:
            h_lines.append(f"int detect_{name}_changed(void);")

        elif entry_type in ("REG_TYPE_MASTER_UINT16", "REG_TYPE_MASTER_UINT32") and not is_array:
            for kind in ("rising", "falling", "toggled"):
                h_lines.append(f"int detect_{name}_{kind}(uint16_t bit_mask);")

        elif entry_type == "REG_TYPE_MASTER_FLOAT_ARRAY":
            h_lines.append(f"int detect_{name}_changed(uint16_t index);")
            h_lines.append(f"int detect_{name}_any_changed(void);")

        elif entry_type in ("REG_TYPE_MASTER_UINT16_ARRAY", "REG_TYPE_MASTER_UINT32_ARRAY"):
            for kind in ("rising", "falling", "toggled"):
                h_lines.append(f"int detect_{name}_{kind}_edge(uint16_t index, uint16_t bit_mask);")
            h_lines.append(f"int detect_{name}_any_changed(void);")

    h_lines.append("")
    h_lines.append("#endif")

    with open(os.path.join(out_dir, "modbus_reg_edge_master.h"), "w", encoding="utf-8") as f:
        f.write("\n".join(h_lines))

def write_modbus_reg_access_master_c(out_dir, entries):
    c_lines = [
        '#include "modbus_reg_access_master.h"',
        '#include "modbus_reg_map_master.h"',
        '#include "modbus_reg_idx_master.h"',
        '',
    ]

    used_types = {e["raw_var_type"] for e in entries}

    c_lines.extend([
        '/* Access function implementations */',    
        '',
    ])

    if "uint16_t" in used_types:
        c_lines.extend([    
        'static uint16_t read_uint16(const void *ptr) { return *((const uint16_t *)ptr); }',
        'static void write_uint16(void *ptr, uint16_t val) { *((uint16_t *)ptr) = val; }',
        '',
    ])

    if "uint32_t" in used_types:
        c_lines.extend([    
        'static uint32_t read_uint32(const void *ptr) { return *((const uint32_t *)ptr); }',    
        'static void write_uint32(void *ptr, uint32_t val) { *((uint32_t *)ptr) = val; }',
        '',
    ])

    if "float" in used_types:
        c_lines.extend([    
        'static float    read_float (const void *ptr) { return *((const float    *)ptr); }',        
        'static void write_float (void *ptr, float    val) { *((float    *)ptr) = val; }',
        '',
    ])

    c_lines.extend([
        '/* Access function implementations */'
    ])

    def get_base_type(entry_type):
        if "UINT16" in entry_type:
            return "uint16_t"
        elif "UINT32" in entry_type:
            return "uint32_t"
        elif "FLOAT" in entry_type:
            return "float"
        else:
            return "uint16_t"

    def get_read_func(entry_type):
        if "UINT16" in entry_type:
            return "read_uint16"
        elif "UINT32" in entry_type:
            return "read_uint32"
        elif "FLOAT" in entry_type:
            return "read_float"
        else:
            return "read_uint16"

    def get_write_func(entry_type):
        if "UINT16" in entry_type:
            return "write_uint16"
        elif "UINT32" in entry_type:
            return "write_uint32"
        elif "FLOAT" in entry_type:
            return "write_float"
        else:
            return "write_uint16"

    for entry in entries:
        name = entry["name"]
        base_type = get_base_type(entry["type"])
        read_func = get_read_func(entry["type"])
        write_func = get_write_func(entry["type"])
        is_array = entry["length"] > 1

        entry_ref = f"g_reg_table_master[MODBUS_IDX_{name}]"

        # get
        if is_array:
            c_lines.append(f"{base_type} get_{name}(uint16_t index)")
            c_lines.append("{")
            c_lines.append(f"    if (index >= {entry['length']}U) {{ return ({base_type})0; }}")
            c_lines.append(f"    return (({base_type} *)({entry_ref}.ram_ptr))[index];")
            c_lines.append("}")
        else:
            c_lines.append(f"{base_type} get_{name}(void)")
            c_lines.append("{")
            c_lines.append(f"    return {read_func}({entry_ref}.ram_ptr);")
            c_lines.append("}")

        # set
        if is_array:
            c_lines.append(f"int set_{name}(uint16_t index, {base_type} value)")
            c_lines.append("{")
            c_lines.append(f"    const {base_type} min = {read_func}({entry_ref}.min_value);")
            c_lines.append(f"    const {base_type} max = {read_func}({entry_ref}.max_value);")
            c_lines.append(f"    if (index >= {entry['length']}U) {{ return 0; }}")
            c_lines.append(f"    if ((value < min) || (value > max)) return 0;")
            c_lines.append(f"    (({base_type} *)({entry_ref}.ram_ptr))[index] = value;")
            c_lines.append("    return 1;")
            c_lines.append("}")
        else:
            c_lines.append(f"int set_{name}({base_type} value)")
            c_lines.append("{")
            c_lines.append(f"    const {base_type} min = {read_func}({entry_ref}.min_value);")
            c_lines.append(f"    const {base_type} max = {read_func}({entry_ref}.max_value);")
            c_lines.append(f"    if ((value < min) || (value > max)) return 0;")
            c_lines.append(f"    {write_func}({entry_ref}.ram_ptr, value);")
            c_lines.append("    return 1;")
            c_lines.append("}")

        # masked setter
        if not is_array and base_type in ("uint16_t", "uint32_t"):
            c_lines.append(f"int set_{name}_masked({base_type} mask, {base_type} value)")
            c_lines.append("{")
            c_lines.append(f"    {base_type} current = get_{name}();")
            c_lines.append(f"    value &= mask;")
            c_lines.append(f"    current &= (uint16_t)(~mask);")
            c_lines.append(f"    current |= value;")
            c_lines.append(f"    return set_{name}(current);")
            c_lines.append("}")

        # min/max
        c_lines.append(f"{base_type} get_{name}_min(void)")
        c_lines.append("{")
        c_lines.append(f"    return {read_func}({entry_ref}.min_value);")
        c_lines.append("}")

        c_lines.append(f"{base_type} get_{name}_max(void)")
        c_lines.append("{")
        c_lines.append(f"    return {read_func}({entry_ref}.max_value);")
        c_lines.append("}")

        c_lines.append("")

    with open(os.path.join(out_dir, "modbus_reg_access_master.c"), "w", encoding="utf-8") as f:
        f.write("\n".join(c_lines))

def write_modbus_reg_access_master_h(out_dir, entries):
    h_lines = [
        "#ifndef MODBUS_REG_ACCESS_MASTER_H",
        "#define MODBUS_REG_ACCESS_MASTER_H",
        "",
        "#include <stdint.h>",
        "",
        "/* Access function prototypes for Master */"
    ]

    def get_base_type(entry_type):
        if "UINT16" in entry_type:
            return "uint16_t"
        elif "UINT32" in entry_type:
            return "uint32_t"
        elif "FLOAT" in entry_type:
            return "float"
        else:
            return "uint16_t"

    for entry in entries:
        name = entry["name"]
        base_type = get_base_type(entry["type"])
        is_array = entry["length"] > 1

        if is_array:
            h_lines.append(f"{base_type} get_{name}(uint16_t index);")
            h_lines.append(f"int set_{name}(uint16_t index, {base_type} value);")
        else:
            h_lines.append(f"{base_type} get_{name}(void);")
            h_lines.append(f"int set_{name}({base_type} value);")

            if base_type in ("uint16_t", "uint32_t"):
                h_lines.append(f"int set_{name}_masked({base_type} mask, {base_type} value);")

        h_lines.append(f"{base_type} get_{name}_min(void);")
        h_lines.append(f"{base_type} get_{name}_max(void);")
        h_lines.append("")

    h_lines.append("#endif")

    with open(os.path.join(out_dir, "modbus_reg_access_master.h"), "w", encoding="utf-8") as f:
        f.write("\n".join(h_lines))

def write_modbus_reg_idx_master_h(out_dir, entries):
    idx_lines = [
        "#ifndef MODBUS_REG_IDX_MASTER_H",
        "#define MODBUS_REG_IDX_MASTER_H",
        "",
        "#define MODBUS_SLAVE_ADDR 0x01",
        "",
        "/* Master-side Modbus register index definitions */"
    ]

    idx = 0
    for entry in entries:
        base_name = entry["name"]
        length = entry["length"]

        idx_lines.append(f"#define MODBUS_IDX_{base_name}  ({idx})")

        if length > 1:
            for i in range(length):
                idx_lines.append(f"#define MODBUS_IDX_{base_name}_{i}  ({i})")

        idx += 1

    idx_lines.append("")
    idx_lines.append("#endif")

    with open(os.path.join(out_dir, "modbus_reg_idx_master.h"), "w", encoding="utf-8") as f:
        f.write("\n".join(idx_lines))

def map_type_master(var_type: str, is_array: bool) -> str:
    vt = var_type.strip().lower()
    if vt == "uint16_t":
        return "REG_TYPE_MASTER_UINT16_ARRAY" if is_array else "REG_TYPE_MASTER_UINT16"
    elif vt == "uint32_t":
        return "REG_TYPE_MASTER_UINT32_ARRAY" if is_array else "REG_TYPE_MASTER_UINT32"
    elif vt == "float":
        return "REG_TYPE_MASTER_FLOAT_ARRAY" if is_array else "REG_TYPE_MASTER_FLOAT"
    else:
        return "REG_TYPE_MASTER_UINT16"

def format_value_for_init(var_type: str, value: str) -> str:
    try:
        if value.strip() == "":
            value = "0"
        if var_type == "float":
            fval = float(value)
            return f"{int(fval)}.0f" if fval.is_integer() else f"{fval}f"
        elif var_type == "uint16_t":
            return f"{int(value)}U"
        elif var_type == "uint32_t":
            return f"{int(value)}UL"
        else:
            return value
    except Exception:
        return "0"

def generate_static_definition(var_type: str, var_name: str, count: int, default_str: str) -> str:
    init_val = format_value_for_init(var_type, default_str)
    if count == 1:
        return f"static {var_type} {var_name} = {init_val};"
    else:
        init_list = ", ".join([init_val] * count)
        return f"static {var_type} {var_name}[{count}] = {{{init_list}}};"

def get_generic_func_call(var_type: str, base: str) -> str:
    type_lower = var_type.lower()
    if "uint16" in type_lower:
        return f"modbus_sender_generic_u16((const uint16_t *){base}.ram_ptr, {base}.modbus_addr, {base}.length);"
    elif "uint32" in type_lower:
        return f"modbus_sender_generic_u32((const uint32_t *){base}.ram_ptr, {base}.modbus_addr, {base}.length);"
    elif "float" in type_lower:
        return f"modbus_sender_generic_float((const float *){base}.ram_ptr, {base}.modbus_addr, {base}.length);"
    else:
        return f"/* Unsupported type: {var_type} */"

def write_modbus_reg_map_master_h(out_dir, entries, length_defs):
    h_lines = []

    h_lines.append("#ifndef MODBUS_REG_MAP_MASTER_H")
    h_lines.append("#define MODBUS_REG_MAP_MASTER_H")
    h_lines.append("")
    h_lines.append("#include <stdint.h>")
    h_lines.append("")
    h_lines.append("/* 配列長マクロ */")

    for macro, val in length_defs.items():
        h_lines.append(f"#define {macro} ({val}U)")

    h_lines.append("")
    h_lines.append("")
    h_lines.append("typedef enum {")
    h_lines.append("    REG_TYPE_MASTER_UINT16,")
    h_lines.append("    REG_TYPE_MASTER_UINT32,")
    h_lines.append("    REG_TYPE_MASTER_FLOAT,")
    h_lines.append("    REG_TYPE_MASTER_UINT16_ARRAY,")
    h_lines.append("    REG_TYPE_MASTER_UINT32_ARRAY,")
    h_lines.append("    REG_TYPE_MASTER_FLOAT_ARRAY")
    h_lines.append("} reg_type_master_t;")

    h_lines.append("")
    h_lines.append("typedef enum {")
    h_lines.append("    ACCESS_MODE_MASTER_READ,")
    h_lines.append("    ACCESS_MODE_MASTER_WRITE,")
    h_lines.append("    ACCESS_MODE_MASTER_READWRITE")
    h_lines.append("} access_mode_master_t;")

    h_lines.append("")
    h_lines.append("typedef struct {")
    h_lines.append("    const char * name;")
    h_lines.append("    uint16_t     modbus_addr;")
    h_lines.append("    uint16_t     size;")
    h_lines.append("    const void * default_value;")
    h_lines.append("    const void * min_value;")
    h_lines.append("    const void * max_value;")
    h_lines.append("    void       * ram_ptr;")
    h_lines.append("    reg_type_master_t type;")
    h_lines.append("    uint16_t     length;")
    h_lines.append("    access_mode_master_t access;")
    h_lines.append("} reg_table_master_entry_t;")

    h_lines.append("")
    h_lines.append("extern const reg_table_master_entry_t g_reg_table_master[];")
    h_lines.append("extern const uint16_t g_reg_table_master_size;")

    h_lines.append("")
    h_lines.append("#endif")

    with open(os.path.join(out_dir, "modbus_reg_map_master.h"), "w", encoding="utf-8") as f:
        f.write("\n".join(h_lines))

def write_modbus_reg_map_master_c(out_dir, entries):
    c_lines = ["#include \"modbus_reg_map_master.h\"", ""]

    for e in entries:
        c_lines.append(e["ram_decl"])  # static変数定義

        value_type = e['ram_decl'].split()[1]  # 型名（例: uint16_t）
        count = e['length']

        # default/min/max値（初期化済み配列）
        vdef = e['default_value'].split('{')[1].rstrip('}').strip()
        vmin = e['min_value'].split('{')[1].rstrip('}').strip()
        vmax = e['max_value'].split('{')[1].rstrip('}').strip()

        c_lines.append(f"const {value_type} default_{e['name']}[{count}] = {{{vdef}}};")
        c_lines.append(f"const {value_type} min_{e['name']}[{count}] = {{{vmin}}};")
        c_lines.append(f"const {value_type} max_{e['name']}[{count}] = {{{vmax}}};")
        c_lines.append("")

    c_lines.append("const reg_table_master_entry_t g_reg_table_master[] = {")
    for e in entries:
        c_lines.append("    {")
        c_lines.append(f"        \"{e['name']}\",")
        c_lines.append(f"        {e['modbus_addr']},")
        c_lines.append(f"        {e['size']},")
        c_lines.append(f"        default_{e['name']},")
        c_lines.append(f"        min_{e['name']},")
        c_lines.append(f"        max_{e['name']},")
        c_lines.append(f"        {e['ram_ptr']},")
        c_lines.append(f"        {e['type']},")
        c_lines.append(f"        {e['length']},")
        c_lines.append(f"        {e['access']}")
        c_lines.append("    },")
    c_lines.append("};\n")

    c_lines.append("const uint16_t g_reg_table_master_size = (uint16_t)(sizeof(g_reg_table_master) / sizeof(g_reg_table_master[0]));")

    with open(os.path.join(out_dir, "modbus_reg_map_master.c"), "w", encoding="utf-8") as f:
        f.write("\n".join(c_lines))


def write_modbus_sender_gen_c(c_path, entries):
    c_lines = [
        '#include "modbus_sender_gen.h"',
        '#include "modbus_sender_generic.h"',
        '#include "modbus_reg_map_master.h"',
        '#include "modbus_crc_util.h"',
        '#include "modbus_reg_idx_master.h"',        
        '',
        'static uint8_t s_modbus_frame_buf[256];',
        'static uint16_t s_last_read_addr = 0;',
        'static uint16_t s_last_read_regs = 0;',
        ''
    ]

    for e in entries:
        base = f"g_reg_table_master[MODBUS_IDX_{e['name']}]"

        # set 関数の実装        
        c_lines.append(f"void modbus_sender_set_{e['name']}(void)")
        c_lines.append("{")
        c_lines.append(f"    {get_generic_func_call(e['type'], base)}")
        c_lines.append("}")
        c_lines.append("")

        # req関数
        #count_expr = f"get_register_count(\"{e['type']}\", {base}.length)"
        c_lines.append(f"void modbus_sender_req_{e['name']}(void)")
        c_lines.append("{")
        c_lines.append("    uint8_t *frame = s_modbus_frame_buf;")        
        c_lines.append("    uint16_t pos = 0;")
        c_lines.append("    frame[pos++] = MODBUS_SLAVE_ADDR;")
        c_lines.append("    frame[pos++] = 0x03;  // Read Holding Registers")
        c_lines.append(f"    frame[pos++] = (uint8_t)({base}.modbus_addr >> 8);")
        c_lines.append(f"    frame[pos++] = (uint8_t)({base}.modbus_addr & 0xFF);")        
        c_lines.append(f"    uint16_t reg_count = (uint16_t)({base}.size / 2);")
        c_lines.append("    frame[pos++] = (uint8_t)(reg_count >> 8);")
        c_lines.append("    frame[pos++] = (uint8_t)(reg_count & 0xFF);")
        c_lines.append("    uint16_t total_len = modbus_append_crc(frame, pos);")
        c_lines.append("    modbus_sender_output(frame, total_len);")
        c_lines.append("")
        c_lines.append(f"    s_last_read_addr = {base}.modbus_addr;")
        c_lines.append(f"    s_last_read_regs = {base}.size / 2;")
        c_lines.append("}")
        c_lines.append("")

    # ✅ getter関数の追加
    c_lines.extend([
        'uint16_t modbus_sender_get_last_read_addr(void)',
        '{',
        '    return s_last_read_addr;',
        '}',
        '',
        'uint16_t modbus_sender_get_last_read_regs(void)',
        '{',
        '    return s_last_read_regs;',
        '}',
        ''
    ])

    with open(c_path, "w", encoding="utf-8") as f:
        f.write("\n".join(c_lines))

def write_modbus_sender_generic(out_dir):
    # ヘッダファイル
    h_lines = [
        "#ifndef MODBUS_SENDER_GENERIC_H",
        "#define MODBUS_SENDER_GENERIC_H",
        "",
        "#include <stdint.h>",
        "",
        "int modbus_sender_generic_u16(const uint16_t *data, uint16_t addr, uint16_t len);",
        "int modbus_sender_generic_u32(const uint32_t *data, uint16_t addr, uint16_t len);",
        "int modbus_sender_generic_float(const float *data, uint16_t addr, uint16_t len);",
        "",
        "#endif"
    ]
    with open(os.path.join(out_dir, "modbus_sender_generic.h"), "w", encoding="utf-8") as f:
        f.write("\n".join(h_lines))
    
    # 実装ファイル（u16/u32/float 実装）
    c_lines = [
        '#include "modbus_sender_generic.h"',
        '#include "modbus_crc_util.h"',
        '#include "modbus_sender_gen.h"',
        '#include "modbus_reg_idx.h"',
        "",
        "int modbus_sender_generic_u16(const uint16_t *data, uint16_t addr, uint16_t len)",
        "{",
        "    uint8_t frame[256];",
        "    uint16_t i, pos = 0;",
        "",
        "    frame[pos++] = MODBUS_SLAVE_ADDR;",
        "    frame[pos++] = 0x10;  // Write Multiple Registers",
        "    frame[pos++] = (uint8_t)(addr >> 8);",
        "    frame[pos++] = (uint8_t)(addr & 0xFF);",
        "    frame[pos++] = (uint8_t)(len >> 8);",
        "    frame[pos++] = (uint8_t)(len & 0xFF);",
        "    frame[pos++] = (uint8_t)(len * 2);",
        "",
        "    for (i = 0; i < len; ++i) {",
        "        frame[pos++] = (uint8_t)(data[i] >> 8);",
        "        frame[pos++] = (uint8_t)(data[i] & 0xFF);",
        "    }",
        "",
        "    uint16_t total_len = modbus_append_crc(frame, pos);",
        "    modbus_sender_output(frame, total_len);",
        "    return 0;",
     "}",
        "",
        "int modbus_sender_generic_u32(const uint32_t *data, uint16_t addr, uint16_t len)",
        "{",
        "    uint8_t frame[256];",
        "    uint16_t i, pos = 0;",
        "",
        "    frame[pos++] = MODBUS_SLAVE_ADDR;",
        "    frame[pos++] = 0x10;",
        "    frame[pos++] = (uint8_t)(addr >> 8);",
        "    frame[pos++] = (uint8_t)(addr & 0xFF);",
        "    frame[pos++] = (uint8_t)((len * 2) >> 8);",
        "    frame[pos++] = (uint8_t)((len * 2) & 0xFF);",
        "    frame[pos++] = (uint8_t)(len * 4);",
        "",
        "    for (i = 0; i < len; ++i) {",
        "        frame[pos++] = (uint8_t)(data[i] >> 24);",
        "        frame[pos++] = (uint8_t)((data[i] >> 16) & 0xFF);",
        "        frame[pos++] = (uint8_t)((data[i] >> 8) & 0xFF);",
        "        frame[pos++] = (uint8_t)(data[i] & 0xFF);",
        "    }",
        "",
        "    uint16_t total_len = modbus_append_crc(frame, pos);",
        "    modbus_sender_output(frame, total_len);",
        "    return 0;",
        "}",
        "",
        "int modbus_sender_generic_float(const float *data, uint16_t addr, uint16_t len)",
        "{",
        "    uint8_t frame[256];",
        "    uint16_t i, pos = 0;",
        "    union { float f; uint32_t u; } conv;",
        "",
        "    frame[pos++] = MODBUS_SLAVE_ADDR;",
        "    frame[pos++] = 0x10;",
        "    frame[pos++] = (uint8_t)(addr >> 8);",
        "    frame[pos++] = (uint8_t)(addr & 0xFF);",
        "    frame[pos++] = (uint8_t)((len * 2) >> 8);",
        "    frame[pos++] = (uint8_t)((len * 2) & 0xFF);",
        "    frame[pos++] = (uint8_t)(len * 4);",
        "",
        "    for (i = 0; i < len; ++i) {",
        "        conv.f = data[i];",
        "        frame[pos++] = (uint8_t)(conv.u >> 24);",
        "        frame[pos++] = (uint8_t)((conv.u >> 16) & 0xFF);",
        "        frame[pos++] = (uint8_t)((conv.u >> 8) & 0xFF);",
        "        frame[pos++] = (uint8_t)(conv.u & 0xFF);",
        "    }",
        "",
        "    uint16_t total_len = modbus_append_crc(frame, pos);",
        "    modbus_sender_output(frame, total_len);",
        "    return 0;",
        "}"
    ]
    with open(os.path.join(out_dir, "modbus_sender_generic.c"), "w", encoding="utf-8") as f:
        f.write("\n".join(c_lines))

def write_modbus_crc_util(out_dir):
    # ヘッダファイル
    h_lines = [
        "#ifndef MODBUS_CRC_UTIL_H",
        "#define MODBUS_CRC_UTIL_H",
        "",
        "#include <stdint.h>",
        "",
        "uint16_t modbus_append_crc(uint8_t* frame, uint16_t len_without_crc);",
        "",
        "#endif"
    ]
    with open(os.path.join(out_dir, "modbus_crc_util.h"), "w", encoding="utf-8") as f:
        f.write("\n".join(h_lines))

    # 実装ファイル
    c_lines = [
        '#include "modbus_crc_util.h"',
        "",
        "uint16_t modbus_append_crc(uint8_t* frame, uint16_t len_without_crc)",
        "{",
        "    uint16_t crc = 0xFFFFU;",
        "    uint16_t i;",
        "    uint8_t j;",
        "    uint16_t byte;",
        "",
        "    for (i = 0U; i < len_without_crc; ++i)",
        "    {",
        "        byte = (uint16_t)frame[i];",
        "        crc ^= byte;",
        "",
        "        for (j = 0U; j < 8U; ++j)",
        "        {",
        "            if ((crc & 0x0001U) != 0U)",
        "            {",
        "                crc = (uint16_t)((crc >> 1U) ^ 0xA001U);",
        "            }",
        "            else",
        "            {",
        "                crc = (uint16_t)(crc >> 1U);",
        "            }",
        "        }",
        "    }",
        "",
        "    frame[len_without_crc]     = (uint8_t)(crc & 0xFFU);",
        "    frame[len_without_crc + 1] = (uint8_t)((crc >> 8U) & 0xFFU);",
        "",
        "    return (uint16_t)(len_without_crc + 2U);",
        "}"
    ]
    with open(os.path.join(out_dir, "modbus_crc_util.c"), "w", encoding="utf-8") as f:
        f.write("\n".join(c_lines))

def write_modbus_sender_gen_h(out_dir, entries):
    h_lines = [
        "#ifndef MODBUS_SENDER_GEN_H",
        "#define MODBUS_SENDER_GEN_H",
        "",
        "#include <stdint.h>",
        "",
        "/* 自動生成: set/req 関数プロトタイプ */",
        "extern void modbus_sender_output(const uint8_t *data, uint16_t len);",
        ""
    ]

    for e in entries:
        h_lines.append(f"void modbus_sender_set_{e['name']}(void);")
        h_lines.append(f"void modbus_sender_req_{e['name']}(void);")

    h_lines.append("")
    h_lines.append("uint16_t modbus_sender_get_last_read_addr(void);")
    h_lines.append("uint16_t modbus_sender_get_last_read_regs(void);")
    h_lines.append("")
    h_lines.append("#endif")

    with open(os.path.join(out_dir, "modbus_sender_gen.h"), "w", encoding="utf-8") as f:
        f.write("\n".join(h_lines))

def main():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])
    if not file_path:
        print("キャンセルされました")
        return

    reg_table_df = pd.read_excel(file_path, sheet_name="RegisterTable", header=None)
    lengthdefs_df = pd.read_excel(file_path, sheet_name="LengthDefs", header=None)

    header_row_index = None
    for i, row in reg_table_df.iterrows():
        if str(row[2]).strip() == "Reg_Addr":
            header_row_index = i
            break
    if header_row_index is None:
        print("ヘッダ行が見つかりませんでした")
        return

    length_defs = {}
    for _, row in lengthdefs_df.iterrows():
        if str(row[1]).strip().upper() == "EOF":
            break
        macro = row[2]
        value = row[3]
        if pd.notna(macro) and pd.notna(value):
            try:
                length_defs[str(macro).strip()] = int(value)
            except ValueError:
                continue

    entries = []
    for i in range(header_row_index + 1, len(reg_table_df)):
        row = reg_table_df.iloc[i]
        if str(row[1]).strip().upper() == "EOF":
            break

        try:
            var_name = sanitize_var_name(row[3])
            var_type = str(row[4]).strip()
            modbus_addr = int(row[2])
        except (ValueError, TypeError):
            continue

        try:
            length = int(row[6])
        except (ValueError, TypeError):
            length = 1

        vmin_str = str(row[7]).strip() if pd.notna(row[7]) else "0"        # Min
        vmax_str = str(row[8]).strip() if pd.notna(row[8]) else "0xFFFF"   # Max
        vdef_str = str(row[9]).strip() if pd.notna(row[9]) else "0"        # Default

        # vdef/vmin/vmax を文字列で取得（空欄は空文字）
        #vdef_str = str(row[7]).strip() if pd.notna(row[7]) else "0"
        #vmin_str = str(row[8]).strip() if pd.notna(row[5]) else "0"
        #vmax_str = str(row[9]).strip() if pd.notna(row[6]) else "0xFFFF"

        # RAM宣言を追加
        ram_decl = generate_static_definition(var_type, var_name, length, vdef_str)
        ram_ptr = f"{var_name}" if length > 1 else f"&{var_name}"

        def format_array_init(val):
            return ", ".join([format_value_for_init(var_type, val)] * length)

        type_master = map_type_master(var_type, length > 1)

        entries.append({
            "name": var_name,
            "type": type_master,
            "addr": modbus_addr,
            "length": length,
            "ram_decl": ram_decl,
            "ram_ptr": ram_ptr,
            "default_value": f"&({var_type}){{{format_array_init(vdef_str)}}}",
            "min_value": f"&({var_type}){{{format_array_init(vmin_str)}}}",
            "max_value": f"&({var_type}){{{format_array_init(vmax_str)}}}",
            "size": f"sizeof({var_type}) * {length}",
            "raw_var_type": var_type,
            "vdef_str": vdef_str,
            "vmin_str": vmin_str,
            "vmax_str": vmax_str,
            "access": "ACCESS_MODE_MASTER_READWRITE",
        })

    for entry in entries:
        entry["modbus_addr"] = entry["addr"]  # map_master.c側で必要になるので補完

    out_dir = os.path.dirname(file_path)

    write_modbus_reg_map_master_h(out_dir, entries, length_defs)
    write_modbus_reg_map_master_c(out_dir, entries)
    write_modbus_reg_idx_master_h(out_dir, entries)
    write_modbus_reg_access_master_h(out_dir, entries)
    write_modbus_reg_access_master_c(out_dir, entries)
    write_modbus_reg_edge_master_h(out_dir, entries)
    write_modbus_reg_edge_master_c(out_dir, entries)
    write_modbus_reply_handler_master_h(out_dir)
    write_modbus_reply_handler_master_c(out_dir, entries)
    write_modbus_sender_gen_h(out_dir, entries)
    write_modbus_sender_gen_c(os.path.join(out_dir, "modbus_sender_gen.c"), entries)
    write_modbus_sender_generic(out_dir)
    write_modbus_crc_util(out_dir)

    print("✅ スケルトン出力完了:", out_dir)

if __name__ == "__main__":
    main()
