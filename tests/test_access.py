import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from modbus_master_regmap_generator import main


class MasterAccessGenerationTests(unittest.TestCase):
    def _entry(self, access="RW", *, kind="uint16_t", length=1, addr=100, name="value"):
        return main.build_master_entry(
            row_number=1,
            var_name=name,
            var_type=kind,
            modbus_addr=addr,
            length=length,
            min_value="-" if kind == "string" else "0",
            max_value="-" if kind == "string" else "100",
            default_value="ABC" if kind == "string" else "0",
            access=access,
        )

    def _generate(self, writer, *args):
        with tempfile.TemporaryDirectory() as output_dir:
            writer(output_dir, *args)
            return {
                path.name: path.read_text(encoding="utf-8")
                for path in Path(output_dir).iterdir()
            }

    def _sender(self, entries, read_plans=None, write_plans=None):
        with tempfile.TemporaryDirectory() as output_dir:
            path = Path(output_dir) / "modbus_sender_gen.c"
            main.write_modbus_sender_gen_c(path, entries, read_plans, write_plans)
            return path.read_text(encoding="utf-8")

    @staticmethod
    def _function(source, signature):
        start = source.index(signature)
        opening = source.index("{", start)
        depth = 0
        for index in range(opening, len(source)):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    return source[start:index + 1]
        raise AssertionError("Unclosed generated function")

    def test_access_mapping_applies_to_numeric_arrays_and_strings(self):
        for access, expected in (
            ("R", "ACCESS_MODE_MASTER_READ"),
            (" ro ", "ACCESS_MODE_MASTER_READ"),
            ("W", "ACCESS_MODE_MASTER_WRITE"),
            ("rw", "ACCESS_MODE_MASTER_READWRITE"),
        ):
            for kind, length in (("uint16_t", 1), ("uint32_t", 2), ("float", 2), ("string", 8)):
                with self.subTest(access=access, kind=kind):
                    entry = self._entry(access, kind=kind, length=length)
                    self.assertEqual(expected, entry["access"])
                    source = self._generate(main.write_modbus_reg_map_master_c, [entry])[
                        "modbus_reg_map_master.c"
                    ]
                    self.assertRegex(source, re.compile(r'g_reg_table_master\[\] = \{\s*\{\s*100,.*?\b' + expected + r'\s*\}', re.S))

    def test_blank_access_keeps_legacy_rw_and_invalid_values_are_rejected(self):
        for access in ("", "  ", None, pd.NA, float("nan")):
            with self.subTest(access=access):
                self.assertEqual("ACCESS_MODE_MASTER_READWRITE", self._entry(access)["access"])
        for access in ("WR", "read", "R0", "-", 1):
            with self.subTest(access=access), self.assertRaisesRegex(ValueError, "unsupported Access"):
                self._entry(access)

    def test_local_getters_and_setters_remain_available_for_read_only_entries(self):
        for kind, length in (("uint16_t", 1), ("uint32_t", 2), ("float", 1), ("string", 8)):
            with self.subTest(kind=kind):
                entry = self._entry("R", kind=kind, length=length)
                files = self._generate(main.write_modbus_reg_access_master_c, [entry])
                source = files["modbus_reg_access_master.c"]
                getter = "get_master_value_copy" if kind == "string" else "get_master_value"
                self.assertIn(getter, source)
                self.assertIn("set_master_value(", source)
                self.assertNotIn("ACCESS_MODE_MASTER_READ", source)
                self.assertNotIn("modbus_master_write_range_is_allowed", source)
                setter = self._function(source, "int set_master_value(")
                self.assertNotIn("modbus_sender_", setter)

    def test_single_write_is_guarded_but_read_apis_are_unchanged(self):
        for access in ("R", "W", "RW"):
            for kind, length in (("uint16_t", 1), ("uint32_t", 2), ("float", 1), ("string", 8)):
                with self.subTest(access=access, kind=kind):
                    entry = self._entry(access, kind=kind, length=length)
                    source = self._sender([entry])
                    write = self._function(source, "void modbus_sender_set_value(void)")
                    self.assertIn("g_reg_table_master[MODBUS_IDX_value].access == ACCESS_MODE_MASTER_READ", write)
                    self.assertLess(write.index("return;"), write.index("modbus_sender_generic_"))
                    read = self._function(source, "void modbus_sender_req_value(void)")
                    self.assertIn("modbus_sender_send_read_request", read)
                    self.assertNotIn(".access", read)
                    header = self._generate(main.write_modbus_sender_gen_h, [entry])[
                        "modbus_sender_gen.h"
                    ]
                    self.assertIn("void modbus_sender_set_value(void);", header)
                    self.assertIn("void modbus_sender_req_value(void);", header)

    def test_read_only_entry_anywhere_in_write_plan_is_rejected(self):
        for kind, length in (("uint16_t", 3), ("uint32_t", 2), ("float", 1), ("string", 8)):
            for read_only_first in (False, True):
                with self.subTest(kind=kind, read_only_first=read_only_first):
                    count = main.get_register_count(main.map_type_master(kind, length > 1), length)
                    read_only = self._entry("R", kind=kind, length=length, addr=100 if read_only_first else 101, name="read_only")
                    writable = self._entry("RW", addr=100 + count if read_only_first else 100, name="writable")
                    plan = {"group_name": "mixed", "func_suffix": "mixed", "start_addr": 100, "reg_count": count + 1}
                    with patch("builtins.print") as log:
                        self.assertIsNone(main.validate_write_plans([plan], [read_only, writable]))
                    messages = " ".join(str(call.args[0]) for call in log.call_args_list)
                    self.assertIn("read-only", messages)
                    self.assertIn("read_only", messages)
                    self.assertIn("mixed", messages)

    def test_read_only_entries_adjacent_to_write_plan_do_not_block_it(self):
        entries = [
            self._entry("R", addr=99, name="before"),
            self._entry("RW", addr=100, name="writable"),
            self._entry("R", addr=101, name="after"),
        ]
        plan = {"group_name": "one", "func_suffix": "one", "start_addr": 100, "reg_count": 1}
        validated = main.validate_write_plans([plan], entries)
        self.assertIsNotNone(validated)
        self.assertEqual([entries[1]], validated[0]["segments"])

    def test_w_and_rw_write_plan_is_allowed_and_group_read_still_includes_r(self):
        entries = [self._entry("W"), self._entry("RW", addr=101, name="second")]
        plan = {"group_name": "both", "func_suffix": "both", "start_addr": 100, "reg_count": 2}
        validated = main.validate_write_plans([plan], entries)
        self.assertIsNotNone(validated)
        self.assertEqual(entries, validated[0]["segments"])
        source = self._sender(entries, [plan], validated)
        send = self._function(source, "static void modbus_sender_send_write_registers(")
        self.assertLess(send.index("modbus_master_write_range_is_allowed"), send.index("frame[pos++]"))
        self.assertLess(send.index("modbus_master_write_range_is_allowed"), send.index("modbus_sender_output"))
        read_only = self._entry("R")
        read = self._function(self._sender([read_only], [plan], []), "void modbus_sender_req_group_both(void)")
        self.assertIn("modbus_sender_send_read_request", read)
        self.assertNotIn("write_range", read)

    def test_all_direct_generic_writes_check_ranges_before_packing(self):
        source = self._generate(main.write_modbus_sender_generic)["modbus_sender_generic.c"]
        for suffix, count in (("u16", "(uint32_t)len"), ("u32", "(uint32_t)len * 2UL"), ("float", "(uint32_t)len * 2UL"), ("string", "reg_count")):
            with self.subTest(suffix=suffix):
                function = self._function(source, f"int modbus_sender_generic_{suffix}(")
                guard = f"modbus_master_write_range_is_allowed(addr, {count})"
                self.assertIn(guard, function)
                self.assertLess(function.index(guard), function.index("frame[pos++]"))
                self.assertIn("return -1;", function[function.index(guard):function.index("frame[pos++]")])

    def test_range_guard_uses_full_register_span_and_wide_address_arithmetic(self):
        source = self._generate(main.write_modbus_reg_map_master_c, [self._entry("R", kind="string", length=8)])[
            "modbus_reg_map_master.c"
        ]
        guard = self._function(source, "int modbus_master_write_range_is_allowed(")
        for fragment in (
            "uint32_t reg_count", "reg_count == 0UL", "reg_count > 123UL",
            "start_addr = (uint32_t)addr", "end_addr > 0x10000UL",
            "entry->access != ACCESS_MODE_MASTER_READ", "((uint32_t)entry->size / 2UL)",
            "(start_addr < entry_end) && (entry_start < end_addr)",
        ):
            self.assertIn(fragment, guard)
        self.assertNotIn("entry->length /", guard)

    def _workbook(self, path, access, *, with_write_plan=False):
        rows = [
            [None, None, "Reg_Addr", "VarName", "Type", "ArrayLen", "Access", "Min", "Max", "Default"],
            [None, None, 100, "value", "string", 8, access, "-", "-", "ABC"],
            [None, "EOF", None, None, None, None, None, None, None, None],
        ]
        with pd.ExcelWriter(path) as writer:
            pd.DataFrame(rows).to_excel(writer, sheet_name="RegisterTable", header=False, index=False)
            pd.DataFrame([[None, "EOF", None, None]]).to_excel(writer, sheet_name="LengthDefs", header=False, index=False)
            if with_write_plan:
                pd.DataFrame([
                    [None, None, "GroupName", "StartAddr", "EndAddr"],
                    [None, None, "all", 100, 103],
                    [None, "EOF", None, None, None],
                ]).to_excel(writer, sheet_name="WritePlan", header=False, index=False)

    def _run_main(self, workbook_path):
        with patch.object(main.tk, "Tk"), patch.object(main.filedialog, "askopenfilename", return_value=str(workbook_path)), patch("builtins.print") as log:
            main.main()
        return " ".join(str(call.args[0]) for call in log.call_args_list)

    def test_excel_access_column_is_reflected_in_generated_metadata(self):
        for access, expected in (("R", "READ"), ("W", "WRITE"), ("RW", "READWRITE"), (None, "READWRITE")):
            with self.subTest(access=access), tempfile.TemporaryDirectory() as output_dir:
                path = Path(output_dir) / "registers.xlsx"
                self._workbook(path, access)
                self._run_main(path)
                source = (Path(output_dir) / "modbus_reg_map_master.c").read_text(encoding="utf-8")
                self.assertRegex(source, re.compile(r'g_reg_table_master\[\] = \{\s*\{\s*100,.*?ACCESS_MODE_MASTER_' + expected + r'\s*\}', re.S))
                outputs = list(Path(output_dir).glob("*.c")) + list(Path(output_dir).glob("*.h"))
                self.assertEqual(15, len(outputs))
                for output in outputs:
                    data = output.read_bytes()
                    self.assertNotIn(b"\r", data)
                    self.assertFalse(data.startswith(b"\xef\xbb\xbf"))
                    self.assertTrue(data.splitlines()[-1].strip())
                    for line in data.splitlines():
                        self.assertEqual(line, line.rstrip(b" \t"))

    def test_invalid_access_and_read_only_write_plan_stop_before_overwriting_outputs(self):
        for access, with_write_plan, error in (("R0", False, "unsupported Access"), ("R", True, "read-only")):
            with self.subTest(access=access), tempfile.TemporaryDirectory() as output_dir:
                path = Path(output_dir) / "registers.xlsx"
                self._workbook(path, access, with_write_plan=with_write_plan)
                existing = Path(output_dir) / "modbus_reg_map_master.c"
                existing.touch()
                self.assertIn(error, self._run_main(path))
                self.assertEqual(b"", existing.read_bytes())
                self.assertEqual([existing], list(Path(output_dir).glob("*.c")))
                self.assertEqual([], list(Path(output_dir).glob("*.h")))


if __name__ == "__main__":
    unittest.main()
