#!/usr/bin/env python3
"""
Full SAM Hive Parser (Auto‑Mapping + CSV Export)
NSSECU3 Mini Project 3
Author: Your Name
Date: March 2026

- Registry header parsing
- HBIN enumeration
- NK, VK, subkey list parsing
- Recursive tree traversal
- Automatic extraction of user account data (F and V values) using pattern search
- When auto‑parsing fails, prints a hex dump and saves it as a CSV file ready for Excel.
"""

import sys
import struct
import os
from datetime import datetime, timedelta

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
REGF_MAGIC = b"regf"
HBIN_MAGIC = b"hbin"
NK_MAGIC = b"nk"
VK_MAGIC = b"vk"
LIST_MAGICS = {b'lf', b'lh', b'li', b'ri'}

FIRST_HBIN_ABS = 0x1000

REG_TYPES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK",
    7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
}

# Account flags (from Windows SDK)
UF_ACCOUNT_DISABLE = 0x00000002
UF_LOCKOUT = 0x00000010
UF_PASSWD_NOTREQD = 0x00000020
UF_PASSWD_CANT_CHANGE = 0x00000040
UF_NORMAL_ACCOUNT = 0x00000200
UF_DONT_EXPIRE_PASSWD = 0x00010000
UF_PASSWORD_EXPIRED = 0x00800000

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def u16(data, off): return struct.unpack_from("<H", data, off)[0]
def u32(data, off): return struct.unpack_from("<I", data, off)[0]
def i32(data, off): return struct.unpack_from("<i", data, off)[0]
def u64(data, off): return struct.unpack_from("<Q", data, off)[0]

def filetime_to_str(ft):
    if ft == 0 or ft == 0x7FFFFFFFFFFFFFFF:
        return "N/A"
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ft)

def is_printable_ascii(bs):
    return bool(bs) and all(0x20 <= b <= 0x7E for b in bs)

def decode_name(raw):
    if not raw:
        return ""
    if is_printable_ascii(raw):
        return raw.decode("ascii", errors="ignore")
    try:
        s = raw.decode("utf-16le", errors="ignore").rstrip("\x00")
        if s and any(ch.isalnum() for ch in s):
            return s
    except Exception:
        pass
    return raw.decode("ascii", errors="ignore").rstrip("\x00")

def rel_to_abs(rel_off):
    if rel_off == 0xFFFFFFFF or rel_off == 0:
        return None
    return FIRST_HBIN_ABS + rel_off

def hex_dump(data, label="", start=0, length=None):
    if length is None:
        length = len(data)
    print(f"\n{label} (offset 0x{start:04x}):")
    print("Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII")
    for i in range(0, length, 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"{start+i:04x}    {hex_part:<47} {ascii_part}")

# ----------------------------------------------------------------------
# CSV export for hex dump
# ----------------------------------------------------------------------
def save_hex_dump_csv(data, filename):
    """
    Write the hex dump of 'data' to a CSV file.
    The CSV has a header row with offsets (00..0F) and one row per 16 bytes.
    """
    try:
        with open(filename, 'w', newline='') as f:
            # Write header
            f.write("Offset," + ",".join(f"{i:02X}" for i in range(16)) + "\n")
            # Write data rows
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                # Offset column
                line = f"{i:04X},"
                # Byte columns
                line += ",".join(f"{b:02x}" for b in chunk)
                # Pad if last row is short
                if len(chunk) < 16:
                    line += "," * (16 - len(chunk))
                f.write(line + "\n")
        print(f"        [CSV saved to {filename}]")
    except Exception as e:
        print(f"        [Error writing CSV: {e}]")

# ----------------------------------------------------------------------
# Automatic parsing functions (heuristic)
# ----------------------------------------------------------------------
def auto_find_utf16_string(data, min_len=3, max_len=30):
    for i in range(0, len(data) - 2, 2):
        if data[i+1] == 0x00 and 0x20 <= data[i] <= 0x7E:
            j = i
            while j+1 < len(data) and data[j+1] == 0x00 and 0x20 <= data[j] <= 0x7E:
                j += 2
            length = (j - i) // 2
            if min_len <= length <= max_len:
                return i, length
    return None, 0

def auto_find_hash_blocks(data, start_after):
    for i in range(start_after, len(data) - 32):
        b1 = data[i:i+16]
        b2 = data[i+16:i+32]
        if (all(b != 0 for b in b1) and all(b != 0 for b in b2) and
            not all(0x20 <= b <= 0x7E for b in b1) and
            not all(0x20 <= b <= 0x7E for b in b2)):
            return i
    return None

def auto_parse_v(v_data):
    result = {"username": "", "lm_blob": b"", "nt_blob": b"", "offsets": {}}
    name_off, name_len = auto_find_utf16_string(v_data)
    if name_off is None:
        return None
    result["username"] = v_data[name_off:name_off+name_len*2].decode("utf-16le", errors="ignore")
    result["offsets"]["name"] = name_off
    hash_off = auto_find_hash_blocks(v_data, name_off + name_len*2)
    if hash_off:
        result["lm_blob"] = v_data[hash_off:hash_off+16]
        result["nt_blob"] = v_data[hash_off+16:hash_off+32]
        result["offsets"]["hash"] = hash_off
    return result

def auto_find_rid(f_data, expected_rid):
    rid_bytes = struct.pack("<I", expected_rid)
    for off in range(len(f_data) - 3):
        if f_data[off:off+4] == rid_bytes:
            return off
    return None

def auto_parse_f(f_data, expected_rid):
    rid_off = auto_find_rid(f_data, expected_rid)
    if rid_off is None:
        return None
    off_flags = rid_off + 8
    off_last_logon = rid_off + 0x10
    off_last_pwd = rid_off + 0x18
    off_expires = rid_off + 0x20
    off_last_failed = rid_off + 0x28
    off_failed_cnt = rid_off + 0x30
    off_logon_cnt = rid_off + 0x38
    if off_logon_cnt + 4 > len(f_data):
        return None
    account_flags = u32(f_data, off_flags) if off_flags+4 <= len(f_data) else 0
    last_logon = u64(f_data, off_last_logon) if off_last_logon+8 <= len(f_data) else 0
    last_pwd_set = u64(f_data, off_last_pwd) if off_last_pwd+8 <= len(f_data) else 0
    account_expires = u64(f_data, off_expires) if off_expires+8 <= len(f_data) else 0
    last_failed_logon = u64(f_data, off_last_failed) if off_last_failed+8 <= len(f_data) else 0
    failed_logon_count = u32(f_data, off_failed_cnt) if off_failed_cnt+4 <= len(f_data) else 0
    logon_count = u32(f_data, off_logon_cnt) if off_logon_cnt+4 <= len(f_data) else 0
    flags_list = []
    if account_flags & UF_ACCOUNT_DISABLE:   flags_list.append("DISABLED")
    if account_flags & UF_LOCKOUT:           flags_list.append("LOCKED_OUT")
    if account_flags & UF_PASSWD_NOTREQD:    flags_list.append("PASSWORD_NOT_REQUIRED")
    if account_flags & UF_NORMAL_ACCOUNT:    flags_list.append("NORMAL_ACCOUNT")
    if account_flags & UF_DONT_EXPIRE_PASSWD: flags_list.append("PASSWORD_NEVER_EXPIRES")
    if account_flags & UF_PASSWORD_EXPIRED:  flags_list.append("PASSWORD_EXPIRED")
    return {
        "rid": expected_rid,
        "account_flags": account_flags,
        "flags_readable": ", ".join(flags_list) if flags_list else "None",
        "last_logon": filetime_to_str(last_logon),
        "last_pwd_set": filetime_to_str(last_pwd_set),
        "account_expires": filetime_to_str(account_expires),
        "last_failed_logon": filetime_to_str(last_failed_logon),
        "failed_logon_count": failed_logon_count,
        "logon_count": logon_count,
        "offsets": {"rid": rid_off, "flags": off_flags}
    }

# ----------------------------------------------------------------------
# Data structures (unchanged)
# ----------------------------------------------------------------------
class NKRecord:
    def __init__(self, abs_off, rel_off, parent_rel, name, flags,
                 subkey_count, subkey_list_rel, value_count, value_list_rel, timestamp):
        self.abs_off = abs_off
        self.rel_off = rel_off
        self.parent_rel = parent_rel
        self.name = name
        self.flags = flags
        self.subkey_count = subkey_count
        self.subkey_list_rel = subkey_list_rel
        self.value_count = value_count
        self.value_list_rel = value_list_rel
        self.timestamp = timestamp

class VKRecord:
    def __init__(self, abs_off, rel_off, name, value_type, data_len, data_rel, inline, data):
        self.abs_off = abs_off
        self.rel_off = rel_off
        self.name = name
        self.value_type = value_type
        self.data_len = data_len
        self.data_rel = data_rel
        self.inline = inline
        self.data = data

# ----------------------------------------------------------------------
# Main parser class
# ----------------------------------------------------------------------
class SAMParser:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.hbins = []
        self.nk_by_abs = {}
        self.root_abs = None

    # ------------------------------------------------------------------
    # Header and HBIN enumeration (unchanged)
    # ------------------------------------------------------------------
    def parse_header(self):
        if self.data[0:4] != REGF_MAGIC:
            raise ValueError("Not a valid registry hive (missing regf)")

        seq1 = u32(self.data, 0x04)
        seq2 = u32(self.data, 0x08)
        last_write_ft = u64(self.data, 0x0C)
        major = u32(self.data, 0x14)
        minor = u32(self.data, 0x18)
        root_cell_rel = u32(self.data, 0x24)
        hive_bins_size = u32(self.data, 0x28)

        self.root_abs = root_cell_rel + FIRST_HBIN_ABS

        print("[*] Registry hive header")
        print(f"    Magic         : {self.data[0:4].decode(errors='ignore')}")
        print(f"    Sequence      : {seq1}:{seq2}")
        print(f"    Last write    : {filetime_to_str(last_write_ft)}")
        print(f"    Version       : {major}.{minor}")
        print(f"    Root cell rel : 0x{root_cell_rel:08X}")
        print(f"    Root cell abs : 0x{self.root_abs:08X}")
        print(f"    HBIN area size: 0x{hive_bins_size:08X}")

    def parse_hbins(self):
        print("\n[*] Enumerating HBIN blocks")
        off = FIRST_HBIN_ABS
        while off + 0x20 <= len(self.data):
            if self.data[off:off + 4] != HBIN_MAGIC:
                break
            rel = u32(self.data, off + 0x04)
            size = u32(self.data, off + 0x08)
            if size == 0:
                break
            self.hbins.append((off, rel, size))
            off += size
        print(f"[*] Found {len(self.hbins)} HBIN block(s)")
        for i, (abs_off, rel, size) in enumerate(self.hbins):
            print(f"    HBIN[{i}] abs=0x{abs_off:08X} rel=0x{rel:08X} size=0x{size:08X}")

    # ------------------------------------------------------------------
    # NK record parsing (unchanged)
    # ------------------------------------------------------------------
    def try_parse_nk(self, cell_abs):
        try:
            cell_size = i32(self.data, cell_abs)
            if cell_size >= 0:
                return None
            if self.data[cell_abs + 4:cell_abs + 6] != NK_MAGIC:
                return None

            flags = u16(self.data, cell_abs + 0x06)
            timestamp = u64(self.data, cell_abs + 0x08)
            parent_rel = u32(self.data, cell_abs + 0x14)
            subkey_count = u32(self.data, cell_abs + 0x18)
            subkey_list_rel = u32(self.data, cell_abs + 0x20)
            value_count = u32(self.data, cell_abs + 0x24)
            value_list_rel = u32(self.data, cell_abs + 0x28)

            name_len = u16(self.data, cell_abs + 0x4C)
            name_start = cell_abs + 0x50
            name_end = name_start + name_len
            if name_end > len(self.data):
                return None
            raw_name = self.data[name_start:name_end]
            name = decode_name(raw_name).strip()

            rel_off = cell_abs - FIRST_HBIN_ABS
            return NKRecord(
                abs_off=cell_abs,
                rel_off=rel_off,
                parent_rel=parent_rel,
                name=name,
                flags=flags,
                subkey_count=subkey_count,
                subkey_list_rel=subkey_list_rel,
                value_count=value_count,
                value_list_rel=value_list_rel,
                timestamp=timestamp,
            )
        except Exception:
            return None

    def scan_nks(self):
        print("\n[*] Scanning HBIN cells for NK records")
        for hbin_abs, _, hbin_size in self.hbins:
            cell = hbin_abs + 0x20
            hbin_end = hbin_abs + hbin_size
            while cell + 4 <= hbin_end and cell + 4 <= len(self.data):
                try:
                    raw_size = i32(self.data, cell)
                except Exception:
                    break
                if raw_size == 0:
                    break
                step = abs(raw_size)
                if step < 4:
                    break
                nk = self.try_parse_nk(cell)
                if nk:
                    self.nk_by_abs[cell] = nk
                cell += step
        print(f"[*] Total NK records found: {len(self.nk_by_abs)}")

    # ------------------------------------------------------------------
    # Subkey list parsing (unchanged)
    # ------------------------------------------------------------------
    def parse_subkey_list(self, offset_rel, count):
        offset_abs = rel_to_abs(offset_rel)
        if offset_abs is None or offset_abs + 4 > len(self.data):
            return []
        magic = self.data[offset_abs + 4:offset_abs + 6]

        if magic not in LIST_MAGICS:
            offsets = []
            for i in range(count):
                off = u32(self.data, offset_abs + 8 + i * 4)
                if off == 0:
                    break
                nk_abs = rel_to_abs(off)
                if nk_abs:
                    offsets.append(nk_abs)
            return offsets

        if magic == b'ri':
            num_lists = u32(self.data, offset_abs + 8)
            offsets = []
            for i in range(num_lists):
                list_rel = u32(self.data, offset_abs + 12 + i * 4)
                offsets.extend(self.parse_subkey_list(list_rel, 0))
            return offsets

        entries = []
        for i in range(count):
            entry_off = offset_abs + 8 + i * 8
            if entry_off + 4 > len(self.data):
                break
            nk_rel = u32(self.data, entry_off)
            if nk_rel == 0:
                break
            nk_abs = rel_to_abs(nk_rel)
            if nk_abs:
                entries.append(nk_abs)
        return entries

    # ------------------------------------------------------------------
    # Tree traversal (unchanged)
    # ------------------------------------------------------------------
    def get_key_path(self, nk):
        parts = []
        cur = nk
        seen = set()
        while cur is not None:
            if cur.rel_off in seen:
                break
            seen.add(cur.rel_off)
            if cur.parent_rel == 0 or cur.parent_rel == 0xFFFFFFFF:
                if cur.abs_off == self.root_abs:
                    parts.append("ROOT")
                else:
                    parts.append(f"[UNKNOWN_ROOT_{cur.rel_off:08X}]")
                break
            else:
                parts.append(cur.name)
                parent_abs = rel_to_abs(cur.parent_rel)
                cur = self.nk_by_abs.get(parent_abs, None)
                if cur is None:
                    break
        return "\\".join(reversed(parts))

    def find_key_by_path(self, path):
        parts = path.split('\\')
        if parts[0] != "ROOT":
            return None
        current_nk = self.nk_by_abs.get(self.root_abs)
        if not current_nk:
            return None
        for part in parts[1:]:
            if current_nk.subkey_count == 0:
                return None
            child_offsets = self.parse_subkey_list(current_nk.subkey_list_rel, current_nk.subkey_count)
            found = False
            for child_abs in child_offsets:
                child = self.nk_by_abs.get(child_abs)
                if child and child.name == part:
                    current_nk = child
                    found = True
                    break
            if not found:
                return None
        return current_nk

    # ------------------------------------------------------------------
    # VK record parsing (unchanged)
    # ------------------------------------------------------------------
    def parse_vk(self, vk_abs):
        try:
            cell_size = i32(self.data, vk_abs)
            if cell_size >= 0:
                return None
            if self.data[vk_abs + 4:vk_abs + 6] != VK_MAGIC:
                return None
            name_len = u16(self.data, vk_abs + 0x06)
            data_len_raw = u32(self.data, vk_abs + 0x08)
            data_rel = u32(self.data, vk_abs + 0x0C)
            value_type = u32(self.data, vk_abs + 0x10)
            flags = u16(self.data, vk_abs + 0x14)

            name_start = vk_abs + 0x18
            name_end = name_start + name_len
            if name_end > len(self.data):
                return None
            raw_name = self.data[name_start:name_end]

            if flags & 0x0001:
                name = raw_name.decode("ascii", errors="ignore").rstrip("\x00")
            else:
                name = decode_name(raw_name)

            inline = bool(data_len_raw & 0x80000000)
            data_len = data_len_raw & 0x7FFFFFFF

            data = b""
            if inline:
                data = struct.pack("<I", data_rel)[:data_len]
            else:
                data_abs = rel_to_abs(data_rel)
                if data_abs is not None and data_len > 0 and data_abs + data_len <= len(self.data):
                    data = self.data[data_abs:data_abs + data_len]

            rel_off = vk_abs - FIRST_HBIN_ABS
            return VKRecord(
                abs_off=vk_abs,
                rel_off=rel_off,
                name=name,
                value_type=value_type,
                data_len=data_len,
                data_rel=data_rel,
                inline=inline,
                data=data,
            )
        except Exception:
            return None

    def get_vk_list(self, nk):
        vks = []
        if nk.value_count == 0 or nk.value_list_rel in (0, 0xFFFFFFFF):
            return vks
        list_abs = rel_to_abs(nk.value_list_rel)
        if list_abs is None:
            return vks
        for i in range(nk.value_count):
            off_pos = list_abs + i * 4
            if off_pos + 4 > len(self.data):
                break
            vk_rel = u32(self.data, off_pos)
            if vk_rel == 0xFFFFFFFF:
                continue
            vk_abs = rel_to_abs(vk_rel)
            if vk_abs is None:
                continue
            vk = self.parse_vk(vk_abs)
            if vk:
                vks.append(vk)
        return vks

    # ------------------------------------------------------------------
    # Main user extraction (modified to save CSV when hex dump is printed)
    # ------------------------------------------------------------------
    def extract_users(self):
        print("\n[*] Extracting user account data from SAM\\Domains\\Account\\Users")
        target_path = "ROOT\\SAM\\Domains\\Account\\Users"
        users_nk = self.find_key_by_path(target_path)
        if not users_nk:
            print("[-] Users key not found.")
            return

        print(f"[+] Found Users key at rel=0x{users_nk.rel_off:08X}")
        child_offsets = self.parse_subkey_list(users_nk.subkey_list_rel, users_nk.subkey_count)
        print(f"[+] Found {len(child_offsets)} subkeys under Users")

        names_nk = self.find_key_by_path("ROOT\\SAM\\Domains\\Account\\Users\\Names")
        if names_nk:
            print("\n[*] Usernames found under Names:")
            name_offsets = self.parse_subkey_list(names_nk.subkey_list_rel, names_nk.subkey_count)
            for off in name_offsets:
                name_nk = self.nk_by_abs.get(off)
                if name_nk:
                    ts = filetime_to_str(name_nk.timestamp)
                    print(f"    {name_nk.name}  rel=0x{name_nk.rel_off:08X}  timestamp={ts}")

        # Create a directory for CSV dumps
        csv_dir = "hex_dumps"
        if not os.path.exists(csv_dir):
            os.makedirs(csv_dir)

        for child_abs in child_offsets:
            nk = self.nk_by_abs.get(child_abs)
            if not nk or len(nk.name) != 8:
                continue
            try:
                rid = int(nk.name, 16)
            except ValueError:
                continue

            path = self.get_key_path(nk)
            vks = self.get_vk_list(nk)

            print(f"\n[+] RID key: {nk.name} (RID {rid})")
            print(f"    Path      : {path}")
            print(f"    Timestamp : {filetime_to_str(nk.timestamp)}")
            print(f"    Values    : {len(vks)}")

            if not vks:
                print("    [!] No VK records parsed safely from this RID key")
                continue

            f_vk = v_vk = None
            for vk in vks:
                type_name = REG_TYPES.get(vk.value_type, f"UNKNOWN({vk.value_type})")
                print(f"      VK name={vk.name!r} type={type_name} len={vk.data_len} inline={vk.inline}")
                if vk.name == "F":
                    f_vk = vk
                elif vk.name == "V":
                    v_vk = vk

            # ----- F value parsing -----
            if f_vk:
                print(f"      F bytes (first 32): {f_vk.data[:32].hex()}")
                f_info = auto_parse_f(f_vk.data, rid)
                if f_info:
                    print(f"        [Auto] Found RID at offset 0x{f_info['offsets']['rid']:X}")
                    self._print_f_info(f_info)
                else:
                    print("        Could not parse F value automatically.")
                    # Print hex dump and save CSV
                    hex_dump(f_vk.data, f"F value for {nk.name}")
                    csv_filename = os.path.join(csv_dir, f"F_value_RID_{rid}.csv")
                    save_hex_dump_csv(f_vk.data, csv_filename)

            # ----- V value parsing -----
            if v_vk:
                print(f"      V bytes (first 32): {v_vk.data[:32].hex()}")
                v_info = auto_parse_v(v_vk.data)
                if v_info and v_info['username']:
                    print(f"        [Auto] Found username at offset 0x{v_info['offsets']['name']:X}")
                    if 'hash' in v_info['offsets']:
                        print(f"                hashes at offset 0x{v_info['offsets']['hash']:X}")
                    self._print_v_info(v_info)
                else:
                    print("        Could not parse V value automatically.")
                    # Print hex dump and save CSV
                    hex_dump(v_vk.data, f"V value for {nk.name}")
                    csv_filename = os.path.join(csv_dir, f"V_value_RID_{rid}.csv")
                    save_hex_dump_csv(v_vk.data, csv_filename)

    def _print_f_info(self, f_info):
        print(f"        RID in F           : {f_info['rid']}")
        print(f"        Account flags      : 0x{f_info['account_flags']:08X} ({f_info['flags_readable']})")
        print(f"        Last logon         : {f_info['last_logon']}")
        print(f"        Last password set  : {f_info['last_pwd_set']}")
        print(f"        Account expires    : {f_info['account_expires']}")
        print(f"        Last failed logon  : {f_info['last_failed_logon']}")
        print(f"        Failed logon count : {f_info['failed_logon_count']}")
        print(f"        Logon count        : {f_info['logon_count']}")

    def _print_v_info(self, v_info):
        print(f"        Username  : {v_info['username']}")
        lm = v_info.get('lm_blob', b'')
        nt = v_info.get('nt_blob', b'')
        print(f"        LM blob   : {lm.hex()}")
        print(f"        NT blob   : {nt.hex()}")

    # ------------------------------------------------------------------
    # Search for interesting keys (optional, unchanged)
    # ------------------------------------------------------------------
    def search_interesting(self):
        print("\n[*] Searching for interesting names directly")
        exact_targets = {"SAM", "Domains", "Account", "Users", "Names",
                         "Administrator", "Guest", "DefaultAccount"}
        found_exact = []
        found_rids = []
        found_probable = []

        for nk in self.nk_by_abs.values():
            if nk.name in exact_targets:
                found_exact.append(nk)
            if len(nk.name) == 8:
                try:
                    rid = int(nk.name, 16)
                    found_rids.append((nk, rid))
                except ValueError:
                    pass
            if nk.name and any(c.isalpha() for c in nk.name):
                if nk.name not in {"ROOT", "RXACT"} and len(nk.name) < 64:
                    found_probable.append(nk)

        if found_exact:
            print("\n[+] Exact target names found")
            for nk in found_exact:
                print(f"    name={nk.name} rel=0x{nk.rel_off:08X} parent=0x{nk.parent_rel:08X} subkeys={nk.subkey_count} values={nk.value_count}")
        if found_rids:
            print("\n[+] RID-style keys found")
            for nk, rid in found_rids:
                print(f"    name={nk.name} RID={rid} rel=0x{nk.rel_off:08X} parent=0x{nk.parent_rel:08X} values={nk.value_count}")
        if found_probable:
            print("\n[+] Likely user/group names")
            seen = set()
            for nk in found_probable:
                if nk.name not in seen:
                    seen.add(nk.name)
                    print(f"    {nk.name}")

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def run(self):
        self.parse_header()
        self.parse_hbins()
        self.scan_nks()
        self.search_interesting()
        self.extract_users()


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    if len(sys.argv) != 2:
        print("Usage: py sam_parser.py <SAM_hive_file>")
        sys.exit(1)

    parser = SAMParser(sys.argv[1])
    parser.run()


if __name__ == "__main__":
    main()