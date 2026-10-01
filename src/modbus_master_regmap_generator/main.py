import pandas as pd
import tkinter as tk
from tkinter import filedialog
import os
import re
import textwrap

DEFAULT_MODBUS_SLAVE_ADDR = 1  # Configシート未設定時のフォールバック値
MODBUS_MAX_WRITE_REGISTERS = 123
MODBUS_MAX_STRING_BYTES = MODBUS_MAX_WRITE_REGISTERS * 2


def normalize_master_type(var_type: str) -> str:
    """Normalize and validate an Excel Type value."""
    normalized = str(var_type).strip().lower()
    if normalized in ("string", "char"):
        return "string"
    if normalized in ("uint16_t", "uint32_t", "float"):
        return normalized
    raise ValueError(
        f"unsupported Type '{var_type}'. "
        "Use uint16_t, uint32_t, float, string, or CHAR."
    )


def is_string_type(var_type: str) -> bool:
    return normalize_master_type(var_type) == "string"


def resolve_string_default(raw_value) -> str:
    if pd.isna(raw_value) or str(raw_value).strip() == "":
        raise ValueError("string Default must not be blank. Use '-' for an empty string.")

    value = str(raw_value)
    if value == "-":
        return ""
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def validate_string_entry(length: int, min_value, max_value, default_value) -> str:
    if length < 2:
        raise ValueError(f"string ArrayLen must be at least 2, got {length}.")
    if (length % 2) != 0:
        raise ValueError(f"string ArrayLen must be even, got {length}.")
    if length > MODBUS_MAX_STRING_BYTES:
        raise ValueError(
            f"string ArrayLen must be {MODBUS_MAX_STRING_BYTES} bytes or less, got {length}."
        )
    if pd.isna(min_value) or str(min_value).strip() != "-":
        raise ValueError("string Min must be '-'.")
    if pd.isna(max_value) or str(max_value).strip() != "-":
        raise ValueError("string Max must be '-'.")

    default_text = resolve_string_default(default_value)
    if len(default_text) > length:
        raise ValueError(
            f"string Default length must be {length} bytes or less, got {len(default_text)}."
        )
    for char in default_text:
        code = ord(char)
        if code < 0x20 or code > 0x7E:
            raise ValueError("string Default must contain ASCII printable characters only.")
    return default_text


def format_string_field_initializer(value: str, field_size: int) -> str:
    encoded = [ord(char) for char in value]
    if len(encoded) > field_size:
        raise ValueError("string value exceeds fixed field size")
    encoded.extend([0] * (field_size - len(encoded)))
    return "{" + ", ".join(f"0x{byte:02X}" for byte in encoded) + "}"

# 1レジスタ = 2バイト前提で、型に応じたレジスタ数を計算（未使用）（g_reg_table の size を参照）
def get_register_count(entry_type: str, length: int) -> int:
    if "STRING" in entry_type:
        return length // 2
    elif "UINT16" in entry_type:
        return length
    elif "UINT32" in entry_type or "FLOAT" in entry_type:
        return length * 2
    else:
        return length  # fallback

def sanitize_var_name(var_name: str) -> str:
    return str(var_name).replace(".", "_").strip()


def sanitize_c_identifier(raw_name: str, default_prefix: str = "group") -> str:
    text = str(raw_name).strip()
    if text == "":
        return f"{default_prefix}_unnamed"

    sanitized = re.sub(r"[^0-9A-Za-z_]", "_", text)
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")

    if sanitized == "":
        sanitized = f"{default_prefix}_unnamed"

    if sanitized[0].isdigit():
        sanitized = f"{default_prefix}_{sanitized}"

    return sanitized.lower()


def sanitize_c_function_suffix(raw_name: str, default_suffix: str = "unnamed") -> str:
    text = str(raw_name).strip()
    if text == "":
        return default_suffix

    sanitized = re.sub(r"[^0-9A-Za-z_]", "_", text)
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")

    if sanitized == "":
        return default_suffix

    return sanitized.lower()


def resolve_length(length_cell, length_defs: dict) -> int:
    if pd.isna(length_cell):
        return 1

    if isinstance(length_cell, (int, float)) and not isinstance(length_cell, bool):
        try:
            value = int(length_cell)
            return value if value > 0 else 1
        except (TypeError, ValueError):
            pass

    length_str = str(length_cell).strip()
    if length_str == "":
        return 1

    try:
        value = int(length_str, 0)
        return value if value > 0 else 1
    except (TypeError, ValueError):
        pass

    if length_str in length_defs:
        value = int(length_defs[length_str])
        return value if value > 0 else 1

    print(f"Warning: ArrayLen '{length_cell}' could not be resolved. Using 1 as fallback.")
    return 1


def _parse_positive_int(value) -> int:
    if pd.isna(value):
        raise ValueError("value is NaN")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = int(value)
    else:
        text = str(value).strip()
        if text == "":
            raise ValueError("value is empty")
        parsed = int(text, 0)

    if parsed <= 0:
        raise ValueError("value is not positive")

    return parsed


def _parse_int_auto_base(value) -> int:
    if pd.isna(value):
        raise ValueError("value is NaN")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)

    text = str(value).strip()
    if text == "":
        raise ValueError("value is empty")
    return int(text, 0)


def read_modbus_slave_addr(excel_path: str) -> int:
    try:
        config_df = pd.read_excel(excel_path, sheet_name="Config", header=None)
    except Exception as exc:
        print(f"Warning: failed to read Config sheet ({exc}). Using default Modbus slave address.")
        return DEFAULT_MODBUS_SLAVE_ADDR

    try:
        key_col = config_df.iloc[:, 2]
    except IndexError:
        print("Warning: Config sheet has no column C. Using default Modbus slave address.")
        return DEFAULT_MODBUS_SLAVE_ADDR

    target_row = None
    for row_idx, key in key_col.items():
        if str(key).strip().upper() == "SLAVE_ADDR":
            target_row = row_idx
            break

    if target_row is None:
        print("Warning: SLAVE_ADDR was not found in Config column C. Using default Modbus slave address.")
        return DEFAULT_MODBUS_SLAVE_ADDR

    try:
        raw_value = config_df.loc[target_row, 3]
    except (KeyError, IndexError, ValueError):
        print("Warning: column D value for SLAVE_ADDR is missing. Using default Modbus slave address.")
        return DEFAULT_MODBUS_SLAVE_ADDR

    try:
        return _parse_positive_int(raw_value)
    except ValueError:
        print(f"Warning: SLAVE_ADDR value '{raw_value}' is invalid. Using default Modbus slave address.")
        return DEFAULT_MODBUS_SLAVE_ADDR


def read_read_plan(excel_path: str) -> list:
    try:
        read_plan_df = pd.read_excel(excel_path, sheet_name="ReadPlan", header=None)
    except Exception as exc:
        print(f"Info: ReadPlan sheet was not loaded ({exc}). Group read requests will not be generated.")
        return []

    header_row_index = None
    for i, row in read_plan_df.iterrows():
        if str(row[2] if 2 in row.index else "").strip() == "GroupName":
            header_row_index = i
            break

    if header_row_index is None:
        print("Warning: ReadPlan header 'GroupName' was not found in column C. Group read requests will not be generated.")
        return []

    plans = []
    used_suffixes = set()

    for i in range(header_row_index + 1, len(read_plan_df)):
        row = read_plan_df.iloc[i]

        if str(row[1] if 1 in row.index else "").strip().upper() == "EOF":
            break

        group_cell = row[2] if 2 in row.index else pd.NA
        addr_cell = row[3] if 3 in row.index else pd.NA
        end_addr_cell = row[4] if 4 in row.index else pd.NA

        if pd.isna(group_cell) and pd.isna(addr_cell) and pd.isna(end_addr_cell):
            continue

        group_name = str(group_cell).strip() if pd.notna(group_cell) else ""
        if group_name == "":
            print(f"Warning: ReadPlan row {i + 1} has empty GroupName. Skipping.")
            continue

        try:
            start_addr = _parse_int_auto_base(addr_cell)
            end_addr = _parse_int_auto_base(end_addr_cell)
        except ValueError:
            print(f"Warning: ReadPlan row {i + 1} has invalid StartAddr/endAddr. Skipping.")
            continue

        if not (0 <= start_addr <= 0xFFFF):
            print(f"Warning: ReadPlan row {i + 1} StartAddr '{start_addr}' is out of range (0..65535). Skipping.")
            continue

        if not (0 <= end_addr <= 0xFFFF):
            print(f"Warning: ReadPlan row {i + 1} endAddr '{end_addr}' is out of range (0..65535). Skipping.")
            continue

        if end_addr < start_addr:
            print(f"Warning: ReadPlan row {i + 1} endAddr '{end_addr}' is smaller than StartAddr '{start_addr}'. Skipping.")
            continue

        reg_count = end_addr - start_addr + 1
        if not (1 <= reg_count <= 125):
            print(f"Warning: ReadPlan row {i + 1} register range '{reg_count}' is out of range (1..125). Skipping.")
            continue

        suffix_base = sanitize_c_identifier(group_name, default_prefix="group")
        suffix = suffix_base
        duplicate_index = 2
        while suffix in used_suffixes:
            suffix = f"{suffix_base}_{duplicate_index}"
            duplicate_index += 1

        if suffix != suffix_base:
            print(f"Warning: ReadPlan group '{group_name}' was duplicated. Using function suffix '{suffix}'.")

        used_suffixes.add(suffix)
        plans.append({
            "group_name": group_name,
            "func_suffix": suffix,
            "start_addr": int(start_addr),
            "reg_count": int(reg_count),
        })

    return plans

def read_write_plan(excel_path: str):
    try:
        write_plan_df = pd.read_excel(excel_path, sheet_name="WritePlan", header=None)
    except Exception as exc:
        print(f"Info: WritePlan sheet was not loaded ({exc}). Group write requests will not be generated.")
        return []

    header_row_index = None
    for i, row in write_plan_df.iterrows():
        if str(row[2] if 2 in row.index else "").strip() == "GroupName":
            header_row_index = i
            break

    if header_row_index is None:
        print("Error: WritePlan header 'GroupName' was not found in column C.")
        return None

    plans = []
    errors = []
    used_suffixes = set()

    for i in range(header_row_index + 1, len(write_plan_df)):
        row = write_plan_df.iloc[i]

        if str(row[1] if 1 in row.index else "").strip().upper() == "EOF":
            break

        group_cell = row[2] if 2 in row.index else pd.NA
        addr_cell = row[3] if 3 in row.index else pd.NA
        end_addr_cell = row[4] if 4 in row.index else pd.NA

        if pd.isna(group_cell) and pd.isna(addr_cell) and pd.isna(end_addr_cell):
            continue

        group_name = str(group_cell).strip() if pd.notna(group_cell) else ""
        if group_name == "":
            errors.append(f"WritePlan row {i + 1} has empty GroupName.")
            continue

        try:
            start_addr = _parse_int_auto_base(addr_cell)
            end_addr = _parse_int_auto_base(end_addr_cell)
        except ValueError:
            errors.append(f"WritePlan row {i + 1} has invalid StartAddr/endAddr.")
            continue

        if not (0 <= start_addr <= 0xFFFF):
            errors.append(f"WritePlan row {i + 1} StartAddr '{start_addr}' is out of range (0..65535).")
            continue

        if not (0 <= end_addr <= 0xFFFF):
            errors.append(f"WritePlan row {i + 1} endAddr '{end_addr}' is out of range (0..65535).")
            continue

        if end_addr < start_addr:
            errors.append(f"WritePlan row {i + 1} endAddr '{end_addr}' is smaller than StartAddr '{start_addr}'.")
            continue

        reg_count = end_addr - start_addr + 1
        if not (1 <= reg_count <= 123):
            errors.append(f"WritePlan row {i + 1} register range '{reg_count}' is out of range (1..123).")
            continue

        suffix_base = sanitize_c_function_suffix(group_name)
        suffix = suffix_base
        duplicate_index = 2
        while suffix in used_suffixes:
            suffix = f"{suffix_base}_{duplicate_index}"
            duplicate_index += 1

        if suffix != suffix_base:
            print(f"Warning: WritePlan group '{group_name}' was duplicated. Using function suffix '{suffix}'.")

        used_suffixes.add(suffix)
        plans.append({
            "group_name": group_name,
            "func_suffix": suffix,
            "start_addr": int(start_addr),
            "reg_count": int(reg_count),
        })

    if errors:
        for error in errors:
            print(f"Error: {error}")
        return None

    return plans


def validate_write_plans(write_plans: list, entries: list):
    if not write_plans:
        return []

    errors = []
    addr_to_entry = {}
    entry_spans = []

    for entry in entries:
        start_addr = int(entry["modbus_addr"])
        reg_count = get_register_count(entry["type"], int(entry["length"]))
        end_addr = start_addr + reg_count - 1
        entry_spans.append((entry, start_addr, end_addr))

        for addr in range(start_addr, end_addr + 1):
            if addr in addr_to_entry:
                prev_entry = addr_to_entry[addr]
                errors.append(
                    f"RegisterTable address {addr} is defined by both '{prev_entry['name']}' and '{entry['name']}'."
                )
            else:
                addr_to_entry[addr] = entry

    validated_plans = []

    for plan in write_plans:
        start_addr = int(plan["start_addr"])
        end_addr = start_addr + int(plan["reg_count"]) - 1
        segments = []

        for entry, entry_start, entry_end in entry_spans:
            if entry_end < start_addr or end_addr < entry_start:
                continue

            if entry_start < start_addr or entry_end > end_addr:
                errors.append(
                    f"WritePlan group '{plan['group_name']}' cuts through RegisterTable entry "
                    f"'{entry['name']}' ({entry_start}..{entry_end})."
                )
                continue

            segments.append(entry)

        for addr in range(start_addr, end_addr + 1):
            if addr not in addr_to_entry:
                errors.append(f"WritePlan group '{plan['group_name']}' has undefined address {addr}.")

        enriched_plan = dict(plan)
        enriched_plan["segments"] = sorted(segments, key=lambda entry: int(entry["modbus_addr"]))
        validated_plans.append(enriched_plan)

    if errors:
        for error in errors:
            print(f"Error: {error}")
        return None

    return validated_plans

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
        '    uint8_t func_code;',
        '',
        '    if ((rx_buf == (const uint8_t *)0) || (len < 2U)) return -1;',
        '    func_code = rx_buf[1];',
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
        '    uint8_t byte_count;',
        '    const uint8_t *data;',
        '    uint16_t start_addr;',
        '    uint16_t num_regs;',
        '    uint16_t end_addr;',
        '    uint16_t i;',
        '    uint16_t j;',
        '',
        '    if ((rx_buf == (const uint8_t *)0) || (len < MODBUS_MIN_FRAME_LENGTH)) return -1;',
        '    if (!modbus_validate_crc(rx_buf, len)) return -1;',
        '    if (rx_buf[1] != MODBUS_FUNC_READ_HOLDING_REGS) return -1;',
        '',
        '    byte_count = rx_buf[2];',
        '    if (len < (uint16_t)(3U + byte_count + 2U)) return -1;',
        '    data = &rx_buf[3];',
        '',
        '    start_addr = modbus_sender_get_last_read_addr();',
        '    num_regs   = modbus_sender_get_last_read_regs();',
        '    if ((num_regs == 0U) || ((uint16_t)byte_count != (uint16_t)(num_regs * 2U))) return -1;',
        '    end_addr   = (uint16_t)(start_addr + num_regs);',
        '',
        '    for (i = 0; i < g_reg_table_master_size; ++i) {',
        '        const reg_table_master_entry_t *entry = &g_reg_table_master[i];',
        '        uint16_t addr_diff;',
        '        uint16_t offset;',
        '        void *dst;',
        '',
        '        if ((entry->modbus_addr < start_addr) || (entry->modbus_addr >= end_addr)) continue;',
        '',
        '        addr_diff = (uint16_t)(entry->modbus_addr - start_addr);',
        '        offset = (uint16_t)(addr_diff * 2U);',
        '        dst = entry->ram_ptr;',
        '',
        '        switch (entry->type) {',
        '            case REG_TYPE_MASTER_UINT16:',
        '            case REG_TYPE_MASTER_UINT16_ARRAY: {',
        '                uint16_t required_bytes;',
        '                uint16_t *dst_arr;',
        '                const uint16_t *min_arr;',
        '                const uint16_t *max_arr;',
        '',
        '                required_bytes = (uint16_t)(entry->length * 2U);',
        '                if ((offset + required_bytes) > byte_count) return -1;',
        '',
        '                dst_arr = (uint16_t *)dst;',
        '                min_arr = (const uint16_t *)(entry->min_value);',
        '                max_arr = (const uint16_t *)(entry->max_value);',
        '',
        '                for (j = 0; j < entry->length; ++j) {',
        '                    uint16_t incoming;',
        '                    uint16_t elem_offset;',
        '',
        '                    elem_offset = (uint16_t)(offset + (j * 2U));',
        '                    incoming = (uint16_t)(((uint16_t)data[elem_offset] << 8U) | (uint16_t)data[elem_offset + 1U]);',
        '                    if ((incoming < min_arr[j]) || (incoming > max_arr[j])) return -1;',
        '                    if (incoming != dst_arr[j]) dst_arr[j] = incoming;',
        '                }',
        '                break;',
        '            }',
        '            case REG_TYPE_MASTER_UINT32:',
        '            case REG_TYPE_MASTER_UINT32_ARRAY: {',
        '                uint16_t required_bytes;',
        '                uint32_t *dst_arr;',
        '                const uint32_t *min_arr;',
        '                const uint32_t *max_arr;',
        '',
        '                required_bytes = (uint16_t)(entry->length * 4U);',
        '                if ((offset + required_bytes) > byte_count) return -1;',
        '',
        '                dst_arr = (uint32_t *)dst;',
        '                min_arr = (const uint32_t *)(entry->min_value);',
        '                max_arr = (const uint32_t *)(entry->max_value);',
        '',
        '                for (j = 0; j < entry->length; ++j) {',
        '                    uint32_t incoming;',
        '                    uint16_t elem_offset;',
        '',
        '                    elem_offset = (uint16_t)(offset + (j * 4U));',
        '                    incoming = ((uint32_t)data[elem_offset] << 24U) |',
        '                               ((uint32_t)data[elem_offset + 1U] << 16U) |',
        '                               ((uint32_t)data[elem_offset + 2U] << 8U)  |',
        '                               (uint32_t)data[elem_offset + 3U];',
        '                    if ((incoming < min_arr[j]) || (incoming > max_arr[j])) return -1;',
        '                    if (incoming != dst_arr[j]) dst_arr[j] = incoming;',
        '                }',
        '                break;',
        '            }',
        '            case REG_TYPE_MASTER_FLOAT:',
        '            case REG_TYPE_MASTER_FLOAT_ARRAY: {',
        '                uint16_t required_bytes;',
        '                float *dst_arr;',
        '                const float *min_arr;',
        '                const float *max_arr;',
        '',
        '                required_bytes = (uint16_t)(entry->length * 4U);',
        '                if ((offset + required_bytes) > byte_count) return -1;',
        '',
        '                dst_arr = (float *)dst;',
        '                min_arr = (const float *)(entry->min_value);',
        '                max_arr = (const float *)(entry->max_value);',
        '',
        '                for (j = 0; j < entry->length; ++j) {',
        '                    union { uint32_t u; float f; } conv;',
        '                    float incoming;',
        '                    uint16_t elem_offset;',
        '',
        '                    elem_offset = (uint16_t)(offset + (j * 4U));',
        '                    conv.u = ((uint32_t)data[elem_offset] << 24U) |',
        '                             ((uint32_t)data[elem_offset + 1U] << 16U) |',
        '                             ((uint32_t)data[elem_offset + 2U] << 8U)  |',
        '                             (uint32_t)data[elem_offset + 3U];',
        '                    incoming = conv.f;',
        '                    if ((incoming < min_arr[j]) || (incoming > max_arr[j])) return -1;',
        '                    if (!is_float_equal(incoming, dst_arr[j])) dst_arr[j] = incoming;',
        '                }',
        '                break;',
        '            }',
        '            case REG_TYPE_MASTER_STRING: {',
        '                uint16_t required_bytes;',
        '',
        '                required_bytes = entry->length;',
        '                if ((offset + required_bytes) > byte_count) return -1;',
        '                if (modbus_master_string_field_is_valid(',
        '                        (const char *)&data[offset], required_bytes) == 0) return -1;',
        '                if (memcmp(dst, &data[offset], required_bytes) != 0)',
        '                {',
        '                    (void)memcpy(dst, &data[offset], required_bytes);',
        '                }',
        '                break;',
        '            }',
        '            default:',
        '                return -1;',
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
        '    uint16_t i;',
        '    uint8_t j;',
        '    uint16_t byte;',
        '    uint16_t recv_crc;',
        '',
        '    for (i = 0; i < (uint16_t)(length - 2U); ++i) {',
        '        byte = (uint16_t)frame[i];',
        '        crc ^= byte;',
        '        for (j = 0; j < 8U; ++j) {',
        '            if ((crc & 0x0001U) != 0U)',
        '                crc = (uint16_t)((crc >> 1U) ^ 0xA001U);',
        '            else',
            '                crc = (uint16_t)(crc >> 1U);',
        '        }',
        '    }',
        '    recv_crc = (uint16_t)(((uint16_t)frame[length - 1U] << 8U) | frame[length - 2U]);',
        '    return (crc == recv_crc);',
        '}'
    ]

    with open(os.path.join(out_dir, "modbus_reply_handler_master.c"), "w", encoding="utf-8", newline="\n") as f:
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

    with open(os.path.join(out_dir, "modbus_reply_handler_master.h"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(h_lines))

def write_modbus_reg_edge_master_c(out_dir, entries):
    has_string = any(entry["type"] == "REG_TYPE_MASTER_STRING" for entry in entries)
    c_lines = [
        '#include "modbus_reg_access_master.h"',
        '#include "modbus_reg_idx_master.h"',
        '#include "modbus_reg_edge_master.h"',
    ]
    if has_string:
        c_lines.append('#include <string.h>')
    c_lines.append('')

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

        if entry_type == "REG_TYPE_MASTER_STRING":
            c_lines.extend([
                f"int detect_master_{name}_changed(void)",
                "{",
                f"    static char prev[{length}];",
                f"    char curr[{length + 1}];",
                "",
                "    (void)memset(curr, 0, sizeof(curr));",
                f"    if (get_master_{name}_copy(curr, (uint16_t)sizeof(curr)) == 0)",
                "    {",
                "        return 0;",
                "    }",
                f"    if (memcmp(prev, curr, {length}U) != 0)",
                "    {",
                f"        (void)memcpy(prev, curr, {length}U);",
                "        return 1;",
                "    }",
                "    return 0;",
                "}",
            ])

        elif entry_type == "REG_TYPE_MASTER_FLOAT" and not is_array:
            c_lines.extend([
                f"int detect_master_{name}_changed(void)",
                "{",
                f"    static float prev;",
                f"    float curr = get_master_{name}();",
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
            scalar_type = "uint32_t" if entry_type == "REG_TYPE_MASTER_UINT32" else "uint16_t"
            cond_templates = [
                ("rising", "((prev & bit_mask) == 0U) && ((curr & bit_mask) != 0U)"),
                ("falling", "((prev & bit_mask) != 0U) && ((curr & bit_mask) == 0U)"),
                ("toggled", "((prev ^ curr) & bit_mask) != 0U")
            ]

            for kind, cond in cond_templates:
                c_lines.extend([
                    f"int detect_master_{name}_{kind}({scalar_type} bit_mask)",
                    "{",
                    f"    static {scalar_type} prev;",
                    f"    {scalar_type} curr = get_master_{name}();",
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
                f"int detect_master_{name}_changed(uint16_t index)",
                "{",
                f"    static float prev[{length}];",
                "    float curr;",
                f"    if (index >= {length}U) return 0;",
                f"    curr = get_master_{name}(index);",
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
                f"int detect_master_{name}_any_changed(void)",
                "{",
                f"    static float prev[{length}];",
                "    float curr;",
                "    uint16_t i;",
                f"    for (i = 0; i < {length}; ++i)",
                "    {",
                f"        curr = get_master_{name}(i);",
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
            array_type = "uint32_t" if entry_type == "REG_TYPE_MASTER_UINT32_ARRAY" else "uint16_t"

            for kind, cond in [
                ("rising", "((prev[index] & bit_mask) == 0U) && ((curr & bit_mask) != 0U)"),
                ("falling", "((prev[index] & bit_mask) != 0U) && ((curr & bit_mask) == 0U)"),
                ("toggled", "((prev[index] ^ curr) & bit_mask) != 0U")
            ]:
                c_lines.extend([
                    f"int detect_master_{name}_{kind}_edge(uint16_t index, {array_type} bit_mask)",
                    "{",
                    f"    static {array_type} prev[{length}];",
                    f"    {array_type} curr;",
                    f"    if (index >= {length}U) return 0;",
                    f"    curr = get_master_{name}(index);",
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
                f"int detect_master_{name}_any_changed(void)",
                "{",
                f"    static {array_type} prev[{length}];",
                f"    {array_type} curr;",
                "    uint16_t i;",
                f"    for (i = 0; i < {length}; ++i)",
                "    {",
                f"        curr = get_master_{name}(i);",
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
    has_array_entries = any(
        entry["type"] in (
            "REG_TYPE_MASTER_UINT16_ARRAY",
            "REG_TYPE_MASTER_UINT32_ARRAY",
            "REG_TYPE_MASTER_FLOAT_ARRAY",
        )
        for entry in entries
    )

    if has_array_entries:    
        c_lines.append("    uint16_t i = 0;")
    
    c_lines.append("")    

    for entry in entries:
        name = entry["name"]
        entry_type = entry["type"]
        is_array = entry["length"] > 1
        length = entry["length"]

        if entry_type == "REG_TYPE_MASTER_STRING":
            c_lines.append(f"    (void)detect_master_{name}_changed();")
        elif entry_type == "REG_TYPE_MASTER_FLOAT" and not is_array:
            c_lines.append(f"    (void)detect_master_{name}_changed();")
        elif entry_type in ("REG_TYPE_MASTER_UINT16", "REG_TYPE_MASTER_UINT32") and not is_array:
            mask_literal = "0xFFFFFFFFUL" if entry_type == "REG_TYPE_MASTER_UINT32" else "0xFFFFU"
            for kind in ("rising", "falling", "toggled"):
                c_lines.append(f"    (void)detect_master_{name}_{kind}({mask_literal});")
        elif entry_type == "REG_TYPE_MASTER_FLOAT_ARRAY":
            c_lines.append(f"    for (i = 0; i < {length}U; ++i) (void)detect_master_{name}_changed(i);")
            c_lines.append(f"    for (i = 0; i < {length}U; ++i) (void)detect_master_{name}_any_changed();")
        elif entry_type in ("REG_TYPE_MASTER_UINT16_ARRAY", "REG_TYPE_MASTER_UINT32_ARRAY"):
            mask_literal = "0xFFFFFFFFUL" if entry_type == "REG_TYPE_MASTER_UINT32_ARRAY" else "0xFFFFU"
            for kind in ("rising", "falling", "toggled"):
                c_lines.append(f"    for (i = 0; i < {length}U; ++i) (void)detect_master_{name}_{kind}_edge(i, {mask_literal});")
            c_lines.append(f"    for (i = 0; i < {length}U; ++i) (void)detect_master_{name}_any_changed();")
    c_lines.append("}")

    with open(os.path.join(out_dir, "modbus_reg_edge_master.c"), "w", encoding="utf-8", newline="\n") as f:
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

        if entry_type == "REG_TYPE_MASTER_STRING":
            h_lines.append(f"int detect_master_{name}_changed(void);")

        elif entry_type == "REG_TYPE_MASTER_FLOAT" and not is_array:
            h_lines.append(f"int detect_master_{name}_changed(void);")

        elif entry_type in ("REG_TYPE_MASTER_UINT16", "REG_TYPE_MASTER_UINT32") and not is_array:
            mask_type = "uint32_t" if entry_type == "REG_TYPE_MASTER_UINT32" else "uint16_t"
            for kind in ("rising", "falling", "toggled"):
                h_lines.append(f"int detect_master_{name}_{kind}({mask_type} bit_mask);")

        elif entry_type == "REG_TYPE_MASTER_FLOAT_ARRAY":
            h_lines.append(f"int detect_master_{name}_changed(uint16_t index);")
            h_lines.append(f"int detect_master_{name}_any_changed(void);")

        elif entry_type in ("REG_TYPE_MASTER_UINT16_ARRAY", "REG_TYPE_MASTER_UINT32_ARRAY"):
            mask_type = "uint32_t" if entry_type == "REG_TYPE_MASTER_UINT32_ARRAY" else "uint16_t"
            for kind in ("rising", "falling", "toggled"):
                h_lines.append(f"int detect_master_{name}_{kind}_edge(uint16_t index, {mask_type} bit_mask);")
            h_lines.append(f"int detect_master_{name}_any_changed(void);")

    h_lines.append("")
    h_lines.append("#endif")

    with open(os.path.join(out_dir, "modbus_reg_edge_master.h"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(h_lines))

def write_modbus_reg_access_master_c(out_dir, entries):
    has_string = any(entry["type"] == "REG_TYPE_MASTER_STRING" for entry in entries)
    c_lines = [
        '#include "modbus_reg_access_master.h"',
        '#include "modbus_reg_map_master.h"',
        '#include "modbus_reg_idx_master.h"',
    ]
    if has_string:
        c_lines.append('#include <string.h>')
    c_lines.append('')

    used_types = {e["raw_var_type"] for e in entries}

    c_lines.extend([
        '/* Access function implementations */',    
        '',
    ])

    if has_string:
        c_lines.extend([
            'static uint16_t string_length_limited(const char *value, uint16_t max_size)',
            '{',
            '    uint16_t length = 0U;',
            '',
            '    if (value == (const char *)0)',
            '    {',
            '        return max_size;',
            '    }',
            '    while ((length < max_size) && (value[length] != \'\\0\'))',
            '    {',
            '        ++length;',
            '    }',
            '    return length;',
            '}',
            '',
            'static int is_valid_string_value(const char *value, uint16_t max_chars)',
            '{',
            '    uint16_t i;',
            '    unsigned char ch;',
            '',
            '    if ((value == (const char *)0) || (max_chars == 0U))',
            '    {',
            '        return 0;',
            '    }',
            '    for (i = 0U; i < max_chars; ++i)',
            '    {',
            '        ch = (unsigned char)value[i];',
            '        if (ch == \'\\0\')',
            '        {',
            '            return 1;',
            '        }',
            '        if ((ch < 0x20U) || (ch > 0x7EU))',
            '        {',
            '            return 0;',
            '        }',
            '    }',
            '    return value[max_chars] == \'\\0\';',
            '}',
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
        entry_ref = f"g_reg_table_master[MODBUS_IDX_{name}]"

        if entry["type"] == "REG_TYPE_MASTER_STRING":
            length = entry["length"]
            c_lines.extend([
                f"int get_master_{name}_copy(char *dst, uint16_t dst_size)",
                "{",
                f"    const char *src = (const char *)({entry_ref}.ram_ptr);",
                f"    const uint16_t len = modbus_master_string_field_length(src, {length}U);",
                "",
                "    if ((dst == (char *)0) || (dst_size <= len))",
                "    {",
                "        return 0;",
                "    }",
                "    (void)memcpy(dst, src, len);",
                "    dst[len] = '\\0';",
                "    return 1;",
                "}",
                "",
                f"int set_master_{name}(const char *value)",
                "{",
                f"    char temp[{length}];",
                f"    char * const ram = (char *)({entry_ref}.ram_ptr);",
                f"    const uint16_t len = string_length_limited(value, {length + 1}U);",
                "",
                f"    if (is_valid_string_value(value, {length}U) == 0)",
                "    {",
                "        return 0;",
                "    }",
                "    (void)memset(temp, 0, sizeof(temp));",
                "    (void)memcpy(temp, value, len);",
                "    if (memcmp(ram, temp, sizeof(temp)) != 0)",
                "    {",
                "        (void)memcpy(ram, temp, sizeof(temp));",
                "    }",
                "    return 1;",
                "}",
                "",
            ])
            continue

        base_type = get_base_type(entry["type"])
        read_func = get_read_func(entry["type"])
        write_func = get_write_func(entry["type"])
        is_array = entry["length"] > 1

        # get
        if is_array:
            c_lines.append(f"{base_type} get_master_{name}(uint16_t index)")
            c_lines.append("{")
            c_lines.append(f"    if (index >= {entry['length']}U) {{ return ({base_type})0; }}")
            c_lines.append(f"    return (({base_type} *)({entry_ref}.ram_ptr))[index];")
            c_lines.append("}")
        else:
            c_lines.append(f"{base_type} get_master_{name}(void)")
            c_lines.append("{")
            c_lines.append(f"    return {read_func}({entry_ref}.ram_ptr);")
            c_lines.append("}")

        # set
        if is_array:
            c_lines.append(f"int set_master_{name}(uint16_t index, {base_type} value)")
            c_lines.append("{")
            c_lines.append(f"    const {base_type} min = {read_func}({entry_ref}.min_value);")
            c_lines.append(f"    const {base_type} max = {read_func}({entry_ref}.max_value);")
            c_lines.append(f"    if (index >= {entry['length']}U) {{ return 0; }}")
            c_lines.append(f"    if ((value < min) || (value > max)) return 0;")
            c_lines.append(f"    (({base_type} *)({entry_ref}.ram_ptr))[index] = value;")
            c_lines.append("    return 1;")
            c_lines.append("}")
        else:
            c_lines.append(f"int set_master_{name}({base_type} value)")
            c_lines.append("{")
            c_lines.append(f"    const {base_type} min = {read_func}({entry_ref}.min_value);")
            c_lines.append(f"    const {base_type} max = {read_func}({entry_ref}.max_value);")
            c_lines.append(f"    if ((value < min) || (value > max)) return 0;")
            c_lines.append(f"    {write_func}({entry_ref}.ram_ptr, value);")
            c_lines.append("    return 1;")
            c_lines.append("}")

        # masked setter
        if not is_array and base_type in ("uint16_t", "uint32_t"):
            c_lines.append(f"int set_master_{name}_masked({base_type} mask, {base_type} value)")
            c_lines.append("{")
            c_lines.append(f"    {base_type} current = get_master_{name}();")
            c_lines.append(f"    value &= mask;")
            c_lines.append(f"    current &= ({base_type})(~mask);")
            c_lines.append(f"    current |= value;")
            c_lines.append(f"    return set_master_{name}(current);")
            c_lines.append("}")

        # min/max
        c_lines.append(f"{base_type} get_master_{name}_min(void)")
        c_lines.append("{")
        c_lines.append(f"    return {read_func}({entry_ref}.min_value);")
        c_lines.append("}")

        c_lines.append(f"{base_type} get_master_{name}_max(void)")
        c_lines.append("{")
        c_lines.append(f"    return {read_func}({entry_ref}.max_value);")
        c_lines.append("}")

        c_lines.append("")

    with open(os.path.join(out_dir, "modbus_reg_access_master.c"), "w", encoding="utf-8", newline="\n") as f:
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
        if entry["type"] == "REG_TYPE_MASTER_STRING":
            h_lines.append(f"#define MODBUS_MASTER_{name}_MAX_LENGTH  ({entry['length']}U)")
            h_lines.append(
                f"#define MODBUS_MASTER_{name}_BUFFER_SIZE "
                f"(MODBUS_MASTER_{name}_MAX_LENGTH + 1U)"
            )
            h_lines.append(
                f"int get_master_{name}_copy(char *dst, uint16_t dst_size);"
            )
            h_lines.append(f"int set_master_{name}(const char *value);")
            h_lines.append("")
            continue

        base_type = get_base_type(entry["type"])
        is_array = entry["length"] > 1

        if is_array:
            h_lines.append(f"{base_type} get_master_{name}(uint16_t index);")
            h_lines.append(f"int set_master_{name}(uint16_t index, {base_type} value);")
        else:
            h_lines.append(f"{base_type} get_master_{name}(void);")
            h_lines.append(f"int set_master_{name}({base_type} value);")

            if base_type in ("uint16_t", "uint32_t"):
                h_lines.append(f"int set_master_{name}_masked({base_type} mask, {base_type} value);")

        h_lines.append(f"{base_type} get_master_{name}_min(void);")
        h_lines.append(f"{base_type} get_master_{name}_max(void);")
        h_lines.append("")

    h_lines.append("#endif")

    with open(os.path.join(out_dir, "modbus_reg_access_master.h"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(h_lines))

def write_modbus_reg_idx_master_h(out_dir, entries, slave_addr):
    slave_literal = int(slave_addr)
    idx_lines = [
        "#ifndef MODBUS_REG_IDX_MASTER_H",
        "#define MODBUS_REG_IDX_MASTER_H",
        "",
        f"#define MODBUS_SLAVE_ADDR {slave_literal}",
        "",
        "/* Master-side Modbus register index definitions */"
    ]

    idx = 0
    for entry in entries:
        base_name = entry["name"]
        length = entry["length"]

        idx_lines.append(f"#define MODBUS_IDX_{base_name}  ({idx})")

        if length > 1 and entry["type"] != "REG_TYPE_MASTER_STRING":
            for i in range(length):
                idx_lines.append(f"#define MODBUS_IDX_{base_name}_{i}  ({i})")

        idx += 1

    idx_lines.append("")
    idx_lines.append("#endif")

    with open(os.path.join(out_dir, "modbus_reg_idx_master.h"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(idx_lines))

def map_type_master(var_type: str, is_array: bool) -> str:
    vt = normalize_master_type(var_type)
    if vt == "string":
        return "REG_TYPE_MASTER_STRING"
    if vt == "uint16_t":
        return "REG_TYPE_MASTER_UINT16_ARRAY" if is_array else "REG_TYPE_MASTER_UINT16"
    elif vt == "uint32_t":
        return "REG_TYPE_MASTER_UINT32_ARRAY" if is_array else "REG_TYPE_MASTER_UINT32"
    elif vt == "float":
        return "REG_TYPE_MASTER_FLOAT_ARRAY" if is_array else "REG_TYPE_MASTER_FLOAT"
    raise ValueError(f"unsupported Type '{var_type}'.")

def format_value_for_init(var_type: str, value: str) -> str:
    var_type = normalize_master_type(var_type)
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
    var_type = normalize_master_type(var_type)
    if var_type == "string":
        initializer = format_string_field_initializer(default_str, count)
        return f"static char {var_name}[{count}] = {initializer};"

    init_val = format_value_for_init(var_type, default_str)
    if count == 1:
        return f"static {var_type} {var_name} = {init_val};"
    else:
        init_list = ", ".join([init_val] * count)
        return f"static {var_type} {var_name}[{count}] = {{{init_list}}};"

def get_generic_func_call(var_type: str, base: str) -> str:
    type_lower = var_type.lower()
    if "string" in type_lower:
        return f"modbus_sender_generic_string((const char *){base}.ram_ptr, {base}.modbus_addr, {base}.length);"
    elif "uint16" in type_lower:
        return f"modbus_sender_generic_u16((const uint16_t *){base}.ram_ptr, {base}.modbus_addr, {base}.length);"
    elif "uint32" in type_lower:
        return f"modbus_sender_generic_u32((const uint32_t *){base}.ram_ptr, {base}.modbus_addr, {base}.length);"
    elif "float" in type_lower:
        return f"modbus_sender_generic_float((const float *){base}.ram_ptr, {base}.modbus_addr, {base}.length);"
    else:
        return f"/* Unsupported type: {var_type} */"


def build_master_entry(
    row_number: int,
    var_name: str,
    var_type: str,
    modbus_addr: int,
    length: int,
    min_value,
    max_value,
    default_value,
) -> dict:
    normalized_type = normalize_master_type(var_type)
    master_var_name = f"master_{var_name}"

    if normalized_type == "string":
        default_text = validate_string_entry(
            length, min_value, max_value, default_value
        )
        return {
            "name": var_name,
            "type": "REG_TYPE_MASTER_STRING",
            "addr": modbus_addr,
            "modbus_addr": modbus_addr,
            "length": length,
            "ram_decl": generate_static_definition(
                normalized_type, master_var_name, length, default_text
            ),
            "ram_ptr": master_var_name,
            "default_value": default_text,
            "min_value": None,
            "max_value": None,
            "size": f"sizeof(char) * {length}",
            "raw_var_type": normalized_type,
            "vdef_str": default_text,
            "vmin_str": "-",
            "vmax_str": "-",
            "access": "ACCESS_MODE_MASTER_READWRITE",
        }

    vmin_str = str(min_value).strip() if pd.notna(min_value) else "0"
    vmax_str = str(max_value).strip() if pd.notna(max_value) else "0xFFFF"
    vdef_str = str(default_value).strip() if pd.notna(default_value) else "0"
    ram_decl = generate_static_definition(
        normalized_type, master_var_name, length, vdef_str
    )
    ram_ptr = master_var_name if length > 1 else f"&{master_var_name}"

    def format_array_init(value):
        return ", ".join(
            [format_value_for_init(normalized_type, value)] * length
        )

    return {
        "name": var_name,
        "type": map_type_master(normalized_type, length > 1),
        "addr": modbus_addr,
        "modbus_addr": modbus_addr,
        "length": length,
        "ram_decl": ram_decl,
        "ram_ptr": ram_ptr,
        "default_value": f"&({normalized_type}){{{format_array_init(vdef_str)}}}",
        "min_value": f"&({normalized_type}){{{format_array_init(vmin_str)}}}",
        "max_value": f"&({normalized_type}){{{format_array_init(vmax_str)}}}",
        "size": f"sizeof({normalized_type}) * {length}",
        "raw_var_type": normalized_type,
        "vdef_str": vdef_str,
        "vmin_str": vmin_str,
        "vmax_str": vmax_str,
        "access": "ACCESS_MODE_MASTER_READWRITE",
    }

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
    h_lines.append("    REG_TYPE_MASTER_STRING,")
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
    h_lines.append("uint16_t modbus_master_string_field_length(const char *data, uint16_t field_size);")
    h_lines.append("int modbus_master_string_field_is_valid(const char *data, uint16_t field_size);")

    h_lines.append("")
    h_lines.append("#endif")

    with open(os.path.join(out_dir, "modbus_reg_map_master.h"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(h_lines))

def write_modbus_reg_map_master_c(out_dir, entries):
    c_lines = ["#include \"modbus_reg_map_master.h\"", ""]

    for e in entries:
        c_lines.append(e["ram_decl"])  # static変数定義

        if e["type"] == "REG_TYPE_MASTER_STRING":
            default_init = format_string_field_initializer(
                e["default_value"], e["length"]
            )
            c_lines.append(
                f"const char default_master_{e['name']}[{e['length']}] = {default_init};"
            )
            c_lines.append("")
            continue

        value_type = e['ram_decl'].split()[1]  # 型名（例: uint16_t）
        count = e['length']

        # default/min/max値（初期化済み配列）
        vdef = e['default_value'].split('{')[1].rstrip('}').strip()
        vmin = e['min_value'].split('{')[1].rstrip('}').strip()
        vmax = e['max_value'].split('{')[1].rstrip('}').strip()

        c_lines.append(f"const {value_type} default_master_{e['name']}[{count}] = {{{vdef}}};")
        c_lines.append(f"const {value_type} min_master_{e['name']}[{count}] = {{{vmin}}};")
        c_lines.append(f"const {value_type} max_master_{e['name']}[{count}] = {{{vmax}}};")
        c_lines.append("")

    c_lines.append("const reg_table_master_entry_t g_reg_table_master[] = {")
    for e in entries:
        c_lines.append("    {")
        c_lines.append(f"        \"{e['name']}\",")
        c_lines.append(f"        {e['modbus_addr']},")
        c_lines.append(f"        {e['size']},")
        c_lines.append(f"        default_master_{e['name']},")
        if e["type"] == "REG_TYPE_MASTER_STRING":
            c_lines.append("        (const void *)0,")
            c_lines.append("        (const void *)0,")
        else:
            c_lines.append(f"        min_master_{e['name']},")
            c_lines.append(f"        max_master_{e['name']},")
        c_lines.append(f"        {e['ram_ptr']},")
        c_lines.append(f"        {e['type']},")
        c_lines.append(f"        {e['length']},")
        c_lines.append(f"        {e['access']}")
        c_lines.append("    },")
    c_lines.append("};\n")

    c_lines.append("const uint16_t g_reg_table_master_size = (uint16_t)(sizeof(g_reg_table_master) / sizeof(g_reg_table_master[0]));")
    c_lines.extend([
        "",
        "uint16_t modbus_master_string_field_length(const char *data, uint16_t field_size)",
        "{",
        "    uint16_t length = 0U;",
        "",
        "    if (data == (const char *)0)",
        "    {",
        "        return 0U;",
        "    }",
        "    while ((length < field_size) && (data[length] != '\\0'))",
        "    {",
        "        ++length;",
        "    }",
        "    return length;",
        "}",
        "",
        "int modbus_master_string_field_is_valid(const char *data, uint16_t field_size)",
        "{",
        "    uint16_t i;",
        "    int found_nul = 0;",
        "    unsigned char ch;",
        "",
        "    if ((data == (const char *)0) || (field_size == 0U))",
        "    {",
        "        return 0;",
        "    }",
        "    for (i = 0U; i < field_size; ++i)",
        "    {",
        "        ch = (unsigned char)data[i];",
        "        if (found_nul != 0)",
        "        {",
        "            if (ch != 0U)",
        "            {",
        "                return 0;",
        "            }",
        "        }",
        "        else if (ch == 0U)",
        "        {",
        "            found_nul = 1;",
        "        }",
        "        else if ((ch < 0x20U) || (ch > 0x7EU))",
        "        {",
        "            return 0;",
        "        }",
        "    }",
        "    return 1;",
        "}",
    ])

    with open(os.path.join(out_dir, "modbus_reg_map_master.c"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(c_lines))


def write_modbus_sender_gen_c(c_path, entries, read_plans=None, write_plans=None):
    if read_plans is None:
        read_plans = []
    if write_plans is None:
        write_plans = []
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
        '',
        'static void modbus_sender_send_read_request(uint16_t start_addr, uint16_t reg_count)',
        '{',
        '    uint8_t *frame = s_modbus_frame_buf;',
        '    uint16_t pos = 0;',
        '',
        '    frame[pos++] = MODBUS_SLAVE_ADDR;',
        '    frame[pos++] = 0x03;',
        '    frame[pos++] = (uint8_t)(start_addr >> 8U);',
        '    frame[pos++] = (uint8_t)(start_addr & 0xFFU);',
        '    frame[pos++] = (uint8_t)(reg_count >> 8U);',
        '    frame[pos++] = (uint8_t)(reg_count & 0xFFU);',
        '',
        '    modbus_sender_output(frame, modbus_append_crc(frame, pos));',
        '    s_last_read_addr = start_addr;',
        '    s_last_read_regs = reg_count;',
        '}',
        '',
        'static void modbus_sender_send_write_registers(uint16_t start_addr, const uint16_t *regs, uint16_t reg_count)',
        '{',
        '    uint8_t *frame = s_modbus_frame_buf;',
        '    uint16_t pos = 0;',
        '    uint16_t i;',
        '',
        '    if ((regs == (const uint16_t *)0) || (reg_count == 0U) || (reg_count > 123U)) return;',
        '',
        '    frame[pos++] = MODBUS_SLAVE_ADDR;',
        '    frame[pos++] = 0x10;',
        '    frame[pos++] = (uint8_t)(start_addr >> 8U);',
        '    frame[pos++] = (uint8_t)(start_addr & 0xFFU);',
        '    frame[pos++] = (uint8_t)(reg_count >> 8U);',
        '    frame[pos++] = (uint8_t)(reg_count & 0xFFU);',
        '    frame[pos++] = (uint8_t)(reg_count * 2U);',
        '',
        '    for (i = 0U; i < reg_count; ++i) {',
        '        frame[pos++] = (uint8_t)(regs[i] >> 8U);',
        '        frame[pos++] = (uint8_t)(regs[i] & 0xFFU);',
        '    }',
        '',
        '    modbus_sender_output(frame, modbus_append_crc(frame, pos));',
        '}',
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
        c_lines.append(f"    const uint16_t reg_count = (uint16_t)({base}.size / 2U);")
        c_lines.append(f"    modbus_sender_send_read_request((uint16_t){base}.modbus_addr, reg_count);")
        c_lines.append("}")
        c_lines.append("")

    for plan in read_plans:
        c_lines.append(f"void modbus_sender_req_group_{plan['func_suffix']}(void)")
        c_lines.append("{")
        c_lines.append(
            f"    modbus_sender_send_read_request((uint16_t){plan['start_addr']}U, (uint16_t){plan['reg_count']}U);"
        )
        c_lines.append("}")
        c_lines.append("")

    # group write functions
    for plan in write_plans:
        uses_float = any("FLOAT" in entry["type"] for entry in plan["segments"])
        c_lines.append(f"void modbus_sender_set_group_{plan['func_suffix']}(void)")
        c_lines.append("{")
        c_lines.append(f"    uint16_t regs[{plan['reg_count']}U];")
        if uses_float:
            c_lines.append("    union { float f; uint32_t u; } conv;")
        c_lines.append("")

        for entry in plan["segments"]:
            base = f"g_reg_table_master[MODBUS_IDX_{entry['name']}]"
            offset = int(entry["modbus_addr"]) - int(plan["start_addr"])
            entry_type = entry["type"]
            length = int(entry["length"])

            if "UINT16" in entry_type:
                for index in range(length):
                    reg_offset = offset + index
                    c_lines.append(
                        f"    regs[{reg_offset}U] = ((const uint16_t *){base}.ram_ptr)[{index}U];"
                    )
            elif "UINT32" in entry_type:
                for index in range(length):
                    reg_offset = offset + (index * 2)
                    c_lines.append("    {")
                    c_lines.append(
                        f"        const uint32_t value = ((const uint32_t *){base}.ram_ptr)[{index}U];"
                    )
                    c_lines.append(f"        regs[{reg_offset}U] = (uint16_t)(value >> 16U);")
                    c_lines.append(f"        regs[{reg_offset + 1}U] = (uint16_t)(value & 0xFFFFU);")
                    c_lines.append("    }")
            elif "FLOAT" in entry_type:
                for index in range(length):
                    reg_offset = offset + (index * 2)
                    c_lines.append("    {")
                    c_lines.append(f"        conv.f = ((const float *){base}.ram_ptr)[{index}U];")
                    c_lines.append(f"        regs[{reg_offset}U] = (uint16_t)(conv.u >> 16U);")
                    c_lines.append(f"        regs[{reg_offset + 1}U] = (uint16_t)(conv.u & 0xFFFFU);")
                    c_lines.append("    }")
            elif "STRING" in entry_type:
                for index in range(0, length, 2):
                    reg_offset = offset + (index // 2)
                    c_lines.append(
                        f"    regs[{reg_offset}U] = "
                        f"(uint16_t)(((uint16_t)(uint8_t)((const char *){base}.ram_ptr)[{index}U] << 8U) | "
                        f"(uint16_t)(uint8_t)((const char *){base}.ram_ptr)[{index + 1}U]);"
                    )

        c_lines.append("")
        c_lines.append(
            f"    modbus_sender_send_write_registers((uint16_t){plan['start_addr']}U, regs, (uint16_t){plan['reg_count']}U);"
        )
        c_lines.append("}")
        c_lines.append("")

    # getter functions
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

    with open(c_path, "w", encoding="utf-8", newline="\n") as f:
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
        "int modbus_sender_generic_string(const char *data, uint16_t addr, uint16_t byte_len);",
        "",
        "#endif"
    ]
    with open(os.path.join(out_dir, "modbus_sender_generic.h"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(h_lines))
    
    # 実装ファイル（u16/u32/float 実装）
    c_lines = [
        '#include "modbus_sender_generic.h"',
        '#include "modbus_crc_util.h"',
        '#include "modbus_sender_gen.h"',
        '#include "modbus_reg_idx_master.h"',
        '#include "modbus_reg_map_master.h"',
        "",
        "int modbus_sender_generic_u16(const uint16_t *data, uint16_t addr, uint16_t len)",
        "{",
        "    uint8_t frame[256];",
        "    uint16_t i, pos = 0;",
        "",
        "    frame[pos++] = MODBUS_SLAVE_ADDR;",
        "    frame[pos++] = 0x10;",
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
    c_lines.extend([
        "",
        "int modbus_sender_generic_string(const char *data, uint16_t addr, uint16_t byte_len)",
        "{",
        "    uint8_t frame[256];",
        "    uint16_t i;",
        "    uint16_t pos = 0U;",
        "    uint16_t reg_count;",
        "    uint16_t total_len;",
        "",
        "    if ((data == (const char *)0) || (byte_len < 2U) ||",
        "        ((byte_len % 2U) != 0U) || (byte_len > 246U))",
        "    {",
        "        return -1;",
        "    }",
        "    if (modbus_master_string_field_is_valid(data, byte_len) == 0)",
        "    {",
        "        return -1;",
        "    }",
        "    reg_count = (uint16_t)(byte_len / 2U);",
        "    frame[pos++] = MODBUS_SLAVE_ADDR;",
        "    frame[pos++] = 0x10U;",
        "    frame[pos++] = (uint8_t)(addr >> 8U);",
        "    frame[pos++] = (uint8_t)(addr & 0xFFU);",
        "    frame[pos++] = (uint8_t)(reg_count >> 8U);",
        "    frame[pos++] = (uint8_t)(reg_count & 0xFFU);",
        "    frame[pos++] = (uint8_t)byte_len;",
        "",
        "    for (i = 0U; i < byte_len; ++i)",
        "    {",
        "        frame[pos++] = (uint8_t)(unsigned char)data[i];",
        "    }",
        "    total_len = modbus_append_crc(frame, pos);",
        "    modbus_sender_output(frame, total_len);",
        "    return 0;",
        "}",
    ])
    with open(os.path.join(out_dir, "modbus_sender_generic.c"), "w", encoding="utf-8", newline="\n") as f:
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
    with open(os.path.join(out_dir, "modbus_crc_util.h"), "w", encoding="utf-8", newline="\n") as f:
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
    with open(os.path.join(out_dir, "modbus_crc_util.c"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(c_lines))

def write_modbus_sender_gen_h(out_dir, entries, read_plans=None, write_plans=None):
    if read_plans is None:
        read_plans = []
    if write_plans is None:
        write_plans = []

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

    for plan in read_plans:
        h_lines.append(f"void modbus_sender_req_group_{plan['func_suffix']}(void);")

    for plan in write_plans:
        h_lines.append(f"void modbus_sender_set_group_{plan['func_suffix']}(void);")

    h_lines.append("")
    h_lines.append("uint16_t modbus_sender_get_last_read_addr(void);")
    h_lines.append("uint16_t modbus_sender_get_last_read_regs(void);")
    h_lines.append("")
    h_lines.append("#endif")

    with open(os.path.join(out_dir, "modbus_sender_gen.h"), "w", encoding="utf-8", newline="\n") as f:
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
    modbus_slave_addr = read_modbus_slave_addr(file_path)
    read_plans = read_read_plan(file_path)
    write_plans = read_write_plan(file_path)
    if write_plans is None:
        return

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

        length = resolve_length(row[5], length_defs)

        try:
            entries.append(
                build_master_entry(
                    row_number=i + 1,
                    var_name=var_name,
                    var_type=var_type,
                    modbus_addr=modbus_addr,
                    length=length,
                    min_value=row[7],
                    max_value=row[8],
                    default_value=row[9],
                )
            )
        except ValueError as exc:
            print(f"Error: RegisterTable row {i + 1} {var_name}: {exc}")
            return

    write_plans = validate_write_plans(write_plans, entries)
    if write_plans is None:
        return

    out_dir = os.path.dirname(file_path)

    write_modbus_reg_map_master_h(out_dir, entries, length_defs)
    write_modbus_reg_map_master_c(out_dir, entries)
    write_modbus_reg_idx_master_h(out_dir, entries, modbus_slave_addr)
    write_modbus_reg_access_master_h(out_dir, entries)
    write_modbus_reg_access_master_c(out_dir, entries)
    write_modbus_reg_edge_master_h(out_dir, entries)
    write_modbus_reg_edge_master_c(out_dir, entries)
    write_modbus_reply_handler_master_h(out_dir)
    write_modbus_reply_handler_master_c(out_dir, entries)
    write_modbus_sender_gen_h(out_dir, entries, read_plans, write_plans)
    write_modbus_sender_gen_c(os.path.join(out_dir, "modbus_sender_gen.c"), entries, read_plans, write_plans)
    write_modbus_sender_generic(out_dir)
    write_modbus_crc_util(out_dir)

    print("✅ スケルトン出力完了:", out_dir)

if __name__ == "__main__":
    main()
