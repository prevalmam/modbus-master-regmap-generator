import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from modbus_master_regmap_generator import main


class MasterStringGenerationTests(unittest.TestCase):
    def _entry(self, default="ABCDEFGH", *, var_type="string", length=8):
        return main.build_master_entry(
            row_number=1,
            var_name="device_name",
            var_type=var_type,
            modbus_addr=1000,
            length=length,
            min_value="-",
            max_value="-",
            default_value=default,
        )

    def _generate(self, writer, *args):
        with tempfile.TemporaryDirectory() as temp_dir:
            writer(temp_dir, *args)
            for path in Path(temp_dir).iterdir():
                data = path.read_bytes()
                self.assertNotIn(b"\r", data, path.name)
                self.assertFalse(data.startswith(b"\xef\xbb\xbf"), path.name)
                self.assertNotIn(b"modbus_string_field_", data, path.name)
            return {
                path.name: path.read_text(encoding="utf-8")
                for path in Path(temp_dir).iterdir()
            }

    def test_string_and_char_are_fixed_length_string_types(self):
        string_entry = self._entry()
        char_entry = self._entry(var_type="CHAR")

        for entry in (string_entry, char_entry):
            self.assertEqual("REG_TYPE_MASTER_STRING", entry["type"])
            self.assertEqual(8, entry["length"])
            self.assertEqual("sizeof(char) * 8", entry["size"])
            self.assertEqual(4, main.get_register_count(entry["type"], entry["length"]))
            self.assertEqual(
                "static char master_device_name[8] = "
                "{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};",
                entry["ram_decl"],
            )

    def test_string_validation_matches_slave_fixed_field_rules(self):
        with self.assertRaisesRegex(ValueError, "ArrayLen must be even"):
            self._entry(length=7)
        with self.assertRaisesRegex(ValueError, "246 bytes or less"):
            self._entry(length=248)
        with self.assertRaisesRegex(ValueError, "Default length must be 8 bytes or less"):
            self._entry(default="ABCDEFGHI")
        with self.assertRaisesRegex(ValueError, "ASCII printable"):
            self._entry(default="ABC\n")
        with self.assertRaisesRegex(ValueError, "unsupported Type"):
            self._entry(var_type="uint8_t")

    def test_empty_and_literal_dash_defaults_are_distinct(self):
        empty = self._entry(default="-")
        literal = self._entry(default='"-"')

        self.assertEqual("", empty["default_value"])
        self.assertEqual("-", literal["default_value"])
        self.assertIn("{0x00, 0x00", empty["ram_decl"])
        self.assertIn("{0x2D, 0x00", literal["ram_decl"])

    def test_reg_map_generates_string_enum_defaults_and_helpers(self):
        files = self._generate(main.write_modbus_reg_map_master_h, [self._entry()], {})
        header = files["modbus_reg_map_master.h"]
        self.assertIn("REG_TYPE_MASTER_STRING", header)
        self.assertIn("modbus_master_string_field_length", header)
        self.assertIn("modbus_master_string_field_is_valid", header)

        files = self._generate(main.write_modbus_reg_map_master_c, [self._entry("ABC")])
        source = files["modbus_reg_map_master.c"]
        expected = "{0x41, 0x42, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00}"
        self.assertIn(f"static char master_device_name[8] = {expected};", source)
        self.assertIn(f"const char default_master_device_name[8] = {expected};", source)
        self.assertIn("(const void *)0", source)
        self.assertIn("if (found_nul != 0)", source)
        self.assertIn("uint16_t modbus_master_string_field_length(", source)
        self.assertIn("int modbus_master_string_field_is_valid(", source)

    def test_accessors_are_copy_based_and_accept_full_length_values(self):
        entry = self._entry()
        files = self._generate(main.write_modbus_reg_access_master_h, [entry])
        header = files["modbus_reg_access_master.h"]
        self.assertIn("MODBUS_MASTER_device_name_MAX_LENGTH  (8U)", header)
        self.assertIn(
            "int get_master_device_name_copy(char *dst, uint16_t dst_size);",
            header,
        )
        self.assertNotIn("const char *get_master_device_name", header)

        files = self._generate(main.write_modbus_reg_access_master_c, [entry])
        source = files["modbus_reg_access_master.c"]
        self.assertIn("return value[max_chars] == '\\0';", source)
        self.assertIn("string_length_limited(value, 9U)", source)
        self.assertIn("memset(temp, 0, sizeof(temp))", source)
        self.assertIn("modbus_master_string_field_length(src, 8U)", source)

    def test_reply_handler_validates_and_copies_raw_string_bytes(self):
        files = self._generate(main.write_modbus_reply_handler_master_c, [self._entry()])
        source = files["modbus_reply_handler_master.c"]
        self.assertIn("case REG_TYPE_MASTER_STRING", source)
        self.assertIn("required_bytes = entry->length;", source)
        self.assertIn("modbus_master_string_field_is_valid", source)
        self.assertIn("memcpy(dst, &data[offset], required_bytes)", source)

    def test_single_and_group_senders_pack_string_bytes_in_wire_order(self):
        entry = self._entry()
        files = self._generate(main.write_modbus_sender_generic)
        header = files["modbus_sender_generic.h"]
        source = files["modbus_sender_generic.c"]
        self.assertIn("modbus_sender_generic_string", header)
        self.assertIn("reg_count = (uint16_t)(byte_len / 2U);", source)
        self.assertIn("frame[pos++] = (uint8_t)(unsigned char)data[i];", source)
        self.assertIn("modbus_master_string_field_is_valid(data, byte_len)", source)

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "modbus_sender_gen.c"
            plan = {
                "group_name": "name",
                "func_suffix": "name",
                "start_addr": 1000,
                "reg_count": 4,
                "segments": [entry],
            }
            main.write_modbus_sender_gen_c(output, [entry], [], [plan])
            generated = output.read_text(encoding="utf-8")

        self.assertIn(
            "modbus_sender_generic_string((const char *)"
            "g_reg_table_master[MODBUS_IDX_device_name].ram_ptr",
            generated,
        )
        self.assertIn("[0U] << 8U", generated)
        self.assertIn("[1U]);", generated)
        self.assertIn("regs[3U]", generated)

    def test_string_changed_detector_and_index_are_field_based(self):
        entry = self._entry()
        files = self._generate(main.write_modbus_reg_edge_master_h, [entry])
        self.assertIn(
            "int detect_master_device_name_changed(void);",
            files["modbus_reg_edge_master.h"],
        )

        files = self._generate(main.write_modbus_reg_edge_master_c, [entry])
        source = files["modbus_reg_edge_master.c"]
        self.assertIn("static char prev[8];", source)
        self.assertIn("memcmp(prev, curr, 8U)", source)

        files = self._generate(main.write_modbus_reg_idx_master_h, [entry], 1)
        header = files["modbus_reg_idx_master.h"]
        self.assertIn("MODBUS_IDX_device_name", header)
        self.assertNotIn("MODBUS_IDX_device_name_0", header)

    def test_main_accepts_string_from_register_table(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workbook_path = Path(temp_dir) / "registers.xlsx"
            register_rows = [
                [None, None, "Reg_Addr", "VarName", "Type", "ArrayLen", None, "Min", "Max", "Default"],
                [None, None, 1000, "device_name", "string", 8, None, "-", "-", "ABC"],
                [None, "EOF", None, None, None, None, None, None, None, None],
            ]
            length_rows = [[None, "EOF", None, None]]
            with pd.ExcelWriter(workbook_path) as writer:
                pd.DataFrame(register_rows).to_excel(
                    writer, sheet_name="RegisterTable", header=False, index=False
                )
                pd.DataFrame(length_rows).to_excel(
                    writer, sheet_name="LengthDefs", header=False, index=False
                )

            with patch.object(main.tk, "Tk") as tk_mock, patch.object(
                main.filedialog, "askopenfilename", return_value=str(workbook_path)
            ), patch("builtins.print"):
                main.main()

            tk_mock.return_value.withdraw.assert_called_once_with()
            generated_paths = list(Path(temp_dir).glob("*.c")) + list(
                Path(temp_dir).glob("*.h")
            )
            self.assertEqual(15, len(generated_paths))
            for generated_path in generated_paths:
                data = generated_path.read_bytes()
                self.assertNotIn(b"\r", data, generated_path.name)
                self.assertFalse(data.startswith(b"\xef\xbb\xbf"), generated_path.name)
                self.assertNotIn(b"modbus_string_field_", data, generated_path.name)
            generated = (Path(temp_dir) / "modbus_reg_map_master.c").read_text(
                encoding="utf-8"
            )
            self.assertIn("static char master_device_name[8]", generated)
            self.assertIn("REG_TYPE_MASTER_STRING", generated)


if __name__ == "__main__":
    unittest.main()
