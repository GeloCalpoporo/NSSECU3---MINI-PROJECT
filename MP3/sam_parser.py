#!/usr/bin/env python3
"""
Manual SAM Hive Parser for NSSECU3 MP3
- No registry parser libraries used
- Reads the hive as raw bytes
- Traverses SAM\\Domains\\Account\\Users
- Enumerates RID keys and Names mapping
- Extracts F and V raw value data

Author: Jose Angelo / Group
"""

import sys
import struct
import argparse
from datetime import datetime, timedelta


REGF_MAGIC = b"regf"
HBIN_MAGIC = b"hbin"
NK_SIG = b"nk"
VK_SIG = b"vk"

SUBKEY_LIST_SIGS = {b"lf", b"lh", b"li", b"ri"}


def filetime_to_dt(ft):
    if ft == 0:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)
    except Exception:
        return None


def safe_hex(data, limit=64):
    if data is None:
        return ""
    return data[:limit].hex()


class RegistryHive:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()

        self.root_rel = None
        self.root_abs = None
        self.hbins_size = None

    # ----------------------------
    # Basic helpers
    # ----------------------------
    def rel_to_abs(self, rel_off):
        if rel_off in (0xFFFFFFFF,):
            return None
        return 0x1000 + rel_off

    def abs_to_rel(self, abs_off):
        return abs_off - 0x1000

    def read_u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def read_u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def read_i32(self, off):
        return struct.unpack_from("<i", self.data, off)[0]

    def read_u64(self, off):
        return struct.unpack_from("<Q", self.data, off)[0]

    def decode_name(self, raw, compressed=False):
        if raw is None:
            return ""
        try:
            if compressed:
                return raw.decode("latin-1", errors="ignore").rstrip("\x00")
            return raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
        except Exception:
            return ""

    # ----------------------------
    # Hive header
    # ----------------------------
    def parse_header(self):
        if self.data[0:4] != REGF_MAGIC:
            raise ValueError("Not a valid registry hive: missing 'regf'")

        seq1 = self.read_u32(0x04)
        seq2 = self.read_u32(0x08)
        last_write_ft = self.read_u64(0x0C)
        major = self.read_u32(0x14)
        minor = self.read_u32(0x18)
        self.root_rel = self.read_u32(0x24)
        self.root_abs = self.rel_to_abs(self.root_rel)
        self.hbins_size = self.read_u32(0x28)

        print("[*] Registry hive header")
        print(f"    Magic         : regf")
        print(f"    Sequence      : {seq1}:{seq2}")
        print(f"    Last write    : {filetime_to_dt(last_write_ft)}")
        print(f"    Version       : {major}.{minor}")
        print(f"    Root cell rel : 0x{self.root_rel:08X}")
        print(f"    Root cell abs : 0x{self.root_abs:08X}")
        print(f"    HBIN area size: 0x{self.hbins_size:08X}")

    # ----------------------------
    # HBIN walking
    # ----------------------------
    def iter_hbins(self):
        off = 0x1000
        while off + 0x20 <= len(self.data):
            if self.data[off:off + 4] != HBIN_MAGIC:
                break

            rel_off = self.read_u32(off + 0x04)
            size = self.read_u32(off + 0x08)

            yield {
                "abs_off": off,
                "rel_off": rel_off,
                "size": size,
            }

            if size <= 0:
                break
            off += size

    def print_hbins(self):
        hbins = list(self.iter_hbins())
        print(f"[*] Found {len(hbins)} HBIN block(s)")
        for i, hb in enumerate(hbins):
            print(
                f"    HBIN[{i}] abs=0x{hb['abs_off']:08X} rel=0x{hb['rel_off']:08X} size=0x{hb['size']:08X}"
            )

    # ----------------------------
    # Cell parsing
    # ----------------------------
    def get_cell_size(self, abs_off):
        if abs_off is None or abs_off + 4 > len(self.data):
            return None
        return self.read_i32(abs_off)

    def is_allocated_cell(self, abs_off):
        sz = self.get_cell_size(abs_off)
        return sz is not None and sz < 0

    def parse_nk(self, abs_off):
        if abs_off is None or abs_off + 0x54 > len(self.data):
            return None

        cell_size = self.read_i32(abs_off)
        if cell_size >= 0:
            return None

        sig = self.data[abs_off + 4:abs_off + 6]
        if sig != NK_SIG:
            return None

        flags = self.read_u16(abs_off + 0x06)
        last_write_ft = self.read_u64(abs_off + 0x08)
        parent_rel = self.read_u32(abs_off + 0x10)

        num_subkeys = self.read_u32(abs_off + 0x14)
        subkey_list_rel = self.read_u32(abs_off + 0x1C)

        num_values = self.read_u32(abs_off + 0x24)
        value_list_rel = self.read_u32(abs_off + 0x28)

        sk_rel = self.read_u32(abs_off + 0x2C)
        classname_rel = self.read_u32(abs_off + 0x30)

        key_name_len = self.read_u16(abs_off + 0x4C)
        class_name_len = self.read_u16(abs_off + 0x4E)

        compressed = bool(flags & 0x0020)
        name_raw = self.data[abs_off + 0x50:abs_off + 0x50 + key_name_len]
        name = self.decode_name(name_raw, compressed=compressed)

        return {
            "abs_off": abs_off,
            "rel_off": self.abs_to_rel(abs_off),
            "cell_size": cell_size,
            "flags": flags,
            "last_write": filetime_to_dt(last_write_ft),
            "parent_rel": parent_rel,
            "parent_abs": self.rel_to_abs(parent_rel),
            "num_subkeys": num_subkeys,
            "subkey_list_rel": subkey_list_rel,
            "subkey_list_abs": self.rel_to_abs(subkey_list_rel),
            "num_values": num_values,
            "value_list_rel": value_list_rel,
            "value_list_abs": self.rel_to_abs(value_list_rel),
            "sk_rel": sk_rel,
            "classname_rel": classname_rel,
            "key_name_len": key_name_len,
            "class_name_len": class_name_len,
            "compressed_name": compressed,
            "name": name,
        }

    def parse_vk(self, abs_off):
        if abs_off is None or abs_off + 0x18 > len(self.data):
            return None

        cell_size = self.read_i32(abs_off)
        if cell_size >= 0:
            return None

        sig = self.data[abs_off + 4:abs_off + 6]
        if sig != VK_SIG:
            return None

        name_len = self.read_u16(abs_off + 0x06)
        data_len_raw = self.read_u32(abs_off + 0x08)
        data_off_field = self.read_u32(abs_off + 0x0C)
        data_type = self.read_u32(abs_off + 0x10)
        flags = self.read_u16(abs_off + 0x14)

        compressed = bool(flags & 0x0001)
        name_raw = self.data[abs_off + 0x18:abs_off + 0x18 + name_len]
        name = self.decode_name(name_raw, compressed=compressed)

        inline = bool(data_len_raw & 0x80000000)
        data_len = data_len_raw & 0x7FFFFFFF

        if inline:
            data = struct.pack("<I", data_off_field)[:data_len]
            data_abs = None
        else:
            data_abs = self.rel_to_abs(data_off_field)
            if data_abs is None or data_abs + data_len > len(self.data):
                data = None
            else:
                data = self.data[data_abs:data_abs + data_len]

        return {
            "abs_off": abs_off,
            "rel_off": self.abs_to_rel(abs_off),
            "cell_size": cell_size,
            "name_len": name_len,
            "data_len": data_len,
            "data_len_raw": data_len_raw,
            "data_off_field": data_off_field,
            "data_abs": data_abs,
            "data_type": data_type,
            "flags": flags,
            "compressed_name": compressed,
            "name": name,
            "data": data,
            "inline": inline,
        }

    # ----------------------------
    # Subkey list parsing
    # ----------------------------
    def parse_subkey_list(self, abs_off):
        if abs_off is None or abs_off + 4 > len(self.data):
            return []

        cell_size = self.read_i32(abs_off)
        if cell_size >= 0:
            return []

        sig = self.data[abs_off + 4:abs_off + 6]
        if sig not in SUBKEY_LIST_SIGS:
            return []

        count = self.read_u16(abs_off + 0x06)
        entries = []

        if sig in (b"lf", b"lh"):
            # each entry = 4-byte rel offset + 4-byte hash
            base = abs_off + 0x08
            for i in range(count):
                rel = self.read_u32(base + i * 8)
                entries.append(self.rel_to_abs(rel))

        elif sig == b"li":
            # each entry = 4-byte rel offset
            base = abs_off + 0x08
            for i in range(count):
                rel = self.read_u32(base + i * 4)
                entries.append(self.rel_to_abs(rel))

        elif sig == b"ri":
            # each entry points to another subkey list
            base = abs_off + 0x08
            for i in range(count):
                rel = self.read_u32(base + i * 4)
                nested_abs = self.rel_to_abs(rel)
                entries.extend(self.parse_subkey_list(nested_abs))

        return [e for e in entries if e is not None]

    def get_subkeys(self, nk):
        if not nk or nk["subkey_list_abs"] is None:
            return []

        subkey_abs_list = self.parse_subkey_list(nk["subkey_list_abs"])
        out = []
        for sk_abs in subkey_abs_list:
            sk = self.parse_nk(sk_abs)
            if sk:
                out.append(sk)
        return out

    def get_values(self, nk):
        if not nk or nk["value_list_abs"] is None or nk["num_values"] == 0:
            return []

        out = []
        base = nk["value_list_abs"]

        for i in range(nk["num_values"]):
            if base + i * 4 + 4 > len(self.data):
                break
            rel = self.read_u32(base + i * 4)
            abs_off = self.rel_to_abs(rel)
            vk = self.parse_vk(abs_off)
            if vk:
                out.append(vk)

        return out

    # ----------------------------
    # Tree walking
    # ----------------------------
    def get_root_key(self):
        return self.parse_nk(self.root_abs)

    def find_subkey_by_name(self, nk, target_name):
        for sk in self.get_subkeys(nk):
            if sk["name"].lower() == target_name.lower():
                return sk
        return None

    def find_key_by_path(self, path_parts):
        cur = self.get_root_key()
        if not cur:
            return None

        # If first part matches root name, skip it
        parts = list(path_parts)
        if parts and cur["name"].lower() == parts[0].lower():
            parts = parts[1:]

        for part in parts:
            cur = self.find_subkey_by_name(cur, part)
            if not cur:
                return None
        return cur

    # ----------------------------
    # SAM-specific helpers
    # ----------------------------
    def list_users(self):
        users_key = self.find_key_by_path(["SAM", "Domains", "Account", "Users"])
        if not users_key:
            print("[-] Could not find SAM\\Domains\\Account\\Users")
            return

        print("\n[*] Located key: SAM\\Domains\\Account\\Users")
        print(f"    Offset : 0x{users_key['abs_off']:08X}")
        print(f"    Subkeys: {users_key['num_subkeys']}")
        print(f"    Values : {users_key['num_values']}")

        subkeys = self.get_subkeys(users_key)

        rid_keys = []
        names_key = None

        for sk in subkeys:
            nm = sk["name"]
            if nm.lower() == "names":
                names_key = sk
            elif len(nm) == 8 and all(c in "0123456789abcdefABCDEF" for c in nm):
                rid_keys.append(sk)

        print(f"\n[*] RID subkeys found: {len(rid_keys)}")
        for rk in sorted(rid_keys, key=lambda x: x["name"]):
            print(f"    {rk['name']}  abs=0x{rk['abs_off']:08X}")

        # Username -> RID map via Users\Names
        username_to_rid = {}
        if names_key:
            print(f"\n[*] Located key: SAM\\Domains\\Account\\Users\\Names")
            print(f"    Offset : 0x{names_key['abs_off']:08X}")
            for name_subkey in self.get_subkeys(names_key):
                username = name_subkey["name"]
                vals = self.get_values(name_subkey)

                # Default value has empty name ""
                rid = None
                for v in vals:
                    if v["name"] == "" and v["data"] and len(v["data"]) >= 4:
                        rid = struct.unpack_from("<I", v["data"], 0)[0]
                        break

                username_to_rid[username] = rid

            print("\n[*] Username -> RID mapping")
            for uname, rid in sorted(username_to_rid.items()):
                rid_hex = f"{rid:08X}" if rid is not None else "UNKNOWN"
                print(f"    {uname} -> {rid_hex}")
        else:
            print("\n[-] Users\\Names key not found")

        print("\n[*] RID key values (F/V)")
        for rk in sorted(rid_keys, key=lambda x: x["name"]):
            rid_hex = rk["name"]
            rid_dec = int(rid_hex, 16)

            vals = self.get_values(rk)
            f_val = None
            v_val = None
            for v in vals:
                if v["name"] == "F":
                    f_val = v
                elif v["name"] == "V":
                    v_val = v

            print(f"\nRID key {rid_hex} (decimal {rid_dec})")
            print(f"    NK offset     : 0x{rk['abs_off']:08X}")
            print(f"    Last write    : {rk['last_write']}")
            if f_val:
                print(f"    F VK offset   : 0x{f_val['abs_off']:08X}")
                print(f"    F data offset : {('inline' if f_val['inline'] else f'0x{f_val['data_abs']:08X}') if f_val['data'] is not None or f_val['data_abs'] is not None else 'N/A'}")
                print(f"    F data len    : {f_val['data_len']}")
                print(f"    F first bytes : {safe_hex(f_val['data'], 32)}")
            else:
                print("    F value       : not found")

            if v_val:
                print(f"    V VK offset   : 0x{v_val['abs_off']:08X}")
                print(f"    V data offset : {('inline' if v_val['inline'] else f'0x{v_val['data_abs']:08X}') if v_val['data'] is not None or v_val['data_abs'] is not None else 'N/A'}")
                print(f"    V data len    : {v_val['data_len']}")
                print(f"    V first bytes : {safe_hex(v_val['data'], 64)}")
            else:
                print("    V value       : not found")

    def scan_for_magic(self):
        print("\n[*] Quick signature scan")
        for sig in (b"regf", b"hbin", b"nk", b"vk"):
            found = []
            start = 0
            while True:
                idx = self.data.find(sig, start)
                if idx == -1:
                    break
                found.append(idx)
                start = idx + 1
                if len(found) >= 10:
                    break

            hex_list = ", ".join(f"0x{x:08X}" for x in found) if found else "none"
            print(f"    {sig!r}: {hex_list}")


def main():
    ap = argparse.ArgumentParser(description="Manual SAM hive parser")
    ap.add_argument("hive", help="Path to SAM hive file")
    args = ap.parse_args()

    hive = RegistryHive(args.hive)

    try:
        hive.parse_header()
        hive.print_hbins()
        hive.scan_for_magic()
        hive.list_users()
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()