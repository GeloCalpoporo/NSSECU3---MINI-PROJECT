#!/usr/bin/env python3
"""
Full SAM Hive Parser
NSSECU3 Mini Project 3
Author: Your Name
Date: March 2026

Implements:
- Registry header parsing
- HBIN enumeration
- NK record parsing (full structure)
- Subkey list parsing (lf, lh, li, ri)
- VK record parsing (value cells)
- Recursive tree traversal from root
- Extraction of user account data (F and V values)
- Detailed F value interpretation (flags, timestamps)
- Hex dump utility for manual Excel mapping
"""

import sys
import struct
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

# Registry value types
REG_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}

# Account flags (from Windows SDK)
UF_ACCOUNT_DISABLE = 0x00000002
UF_LOCKOUT = 0x00000010
UF_PASSWD_NOTREQD = 0x00000020
UF_PASSWD_CANT_CHANGE = 0x00000040
UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080
UF_NORMAL_ACCOUNT = 0x00000200
UF_INTERDOMAIN_TRUST_ACCOUNT = 0x00000800
UF_WORKSTATION_TRUST_ACCOUNT = 0x00001000
UF_SERVER_TRUST_ACCOUNT = 0x00002000
UF_DONT_EXPIRE_PASSWD = 0x00010000
UF_MNS_LOGON_ACCOUNT = 0x00020000
UF_SMARTCARD_REQUIRED = 0x00040000
UF_TRUSTED_FOR_DELEGATION = 0x00080000
UF_NOT_DELEGATED = 0x00100000
UF_USE_DES_KEY_ONLY = 0x00200000
UF_DONT_REQUIRE_PREAUTH = 0x00400000
UF_PASSWORD_EXPIRED = 0x00800000
UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000
UF_NO_AUTH_DATA_REQUIRED = 0x02000000
UF_PARTIAL_SECRETS_ACCOUNT = 0x04000000

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]

def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def i32(data, off):
    return struct.unpack_from("<i", data, off)[0]

def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]

def filetime_to_str(ft):
    """Convert Windows FILETIME (100‑ns intervals since 1601‑01‑01) to readable string."""
    if ft == 0 or ft == 0x7FFFFFFFFFFFFFFF:  # 0 or max means never / not set
        return "N/A"
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ft)

def is_printable_ascii(bs):
    return bool(bs) and all(0x20 <= b <= 0x7E for b in bs)

def decode_name(raw):
    """Decode a key name (may be ASCII or UTF‑16LE)."""
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
    """Convert a relative offset (from first HBIN) to absolute file offset."""
    if rel_off == 0xFFFFFFFF or rel_off == 0:
        return None
    return FIRST_HBIN_ABS + rel_off

def hex_dump(data, label="", start=0, length=None):
    """Print a hex dump of data in 16‑byte rows (ready for Excel mapping)."""
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
# Data structures
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
        self.nk_by_abs = {}          # absolute offset -> NKRecord
        self.root_abs = None

    # ------------------------------------------------------------------
    # Header and HBIN enumeration
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
    # NK record parsing
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

            # Name length and name (starts at 0x50 in your hive)
            name_len = u16(self.data, cell_abs + 0x4C)
            name_start = cell_abs + 0x50
            name_end = name_start + name_len
            if name_end > len(self.data):
                return None
            raw_name = self.data[name_start:name_end]
            name = decode_name(raw_name).strip()
            if not name:
                return None

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
    # Subkey list parsing (lf, lh, li, ri)
    # ------------------------------------------------------------------
    def parse_subkey_list(self, offset_rel, count):
        """Parse a subkey list (lf, lh, li, ri) and return list of NK absolute offsets."""
        offset_abs = rel_to_abs(offset_rel)
        if offset_abs is None or offset_abs + 4 > len(self.data):
            return []
        magic = self.data[offset_abs + 4:offset_abs + 6]

        # If not a standard list, treat as array of offsets (old style)
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

        # ri = indirect list (list of lists)
        if magic == b'ri':
            num_lists = u32(self.data, offset_abs + 8)
            offsets = []
            for i in range(num_lists):
                list_rel = u32(self.data, offset_abs + 12 + i * 4)
                offsets.extend(self.parse_subkey_list(list_rel, 0))
            return offsets

        # lf, lh, li: each entry is 8 bytes (offset + name hint)
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
    # Tree traversal and path reconstruction
    # ------------------------------------------------------------------
    def get_key_path(self, nk):
        """Return the full registry path of an NK record using parent pointers."""
        parts = []
        cur = nk
        seen = set()
        while cur is not None and cur.parent_rel != 0:
            if cur.rel_off in seen:
                break
            seen.add(cur.rel_off)
            parts.append(cur.name)
            parent_abs = rel_to_abs(cur.parent_rel)
            cur = self.nk_by_abs.get(parent_abs, None)
        # Add root if we reached it
        if cur and cur.name == "ROOT":
            parts.append("ROOT")
        return "\\".join(reversed(parts))

    def find_key_by_path(self, path):
        """Find a key by absolute path (e.g., 'ROOT\\SAM\\Domains\\Account\\Users')."""
        parts = path.split('\\')
        if parts[0] != "ROOT":
            return None
        current_abs = self.root_abs
        for part in parts[1:]:
            nk = self.nk_by_abs.get(current_abs)
            if not nk or nk.subkey_count == 0:
                return None
            child_offsets = self.parse_subkey_list(nk.subkey_list_rel, nk.subkey_count)
            found = False
            for child_abs in child_offsets:
                child = self.nk_by_abs.get(child_abs)
                if child and child.name == part:
                    current_abs = child_abs
                    found = True
                    break
            if not found:
                return None
        return self.nk_by_abs.get(current_abs)

    # ------------------------------------------------------------------
    # VK record parsing
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

            # Decode name (ASCII if flag 0x0001 set)
            if flags & 0x0001:
                name = raw_name.decode("ascii", errors="ignore").rstrip("\x00")
            else:
                name = decode_name(raw_name)

            inline = bool(data_len_raw & 0x80000000)
            data_len = data_len_raw & 0x7FFFFFFF

            data = b""
            if inline:
                # Inline data is stored in the data_rel field itself
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
        """Return list of VK records belonging to an NK."""
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
    # F value parsing (user metadata)
    # ------------------------------------------------------------------
    def parse_f_value(self, f_data):
        """Extract account information from the F value."""
        if len(f_data) < 0x40:
            return None

        rid = u32(f_data, 0x00)
        account_flags = u32(f_data, 0x08)
        last_logon = u64(f_data, 0x10)
        last_pwd_set = u64(f_data, 0x18)
        account_expires = u64(f_data, 0x20)
        last_failed_logon = u64(f_data, 0x28)
        failed_logon_count = u32(f_data, 0x30)
        logon_count = u32(f_data, 0x38)

        # Decode flags
        flags_list = []
        if account_flags & UF_ACCOUNT_DISABLE:
            flags_list.append("DISABLED")
        if account_flags & UF_LOCKOUT:
            flags_list.append("LOCKED_OUT")
        if account_flags & UF_PASSWD_NOTREQD:
            flags_list.append("PASSWORD_NOT_REQUIRED")
        if account_flags & UF_PASSWD_CANT_CHANGE:
            flags_list.append("PASSWORD_CANT_CHANGE")
        if account_flags & UF_NORMAL_ACCOUNT:
            flags_list.append("NORMAL_ACCOUNT")
        if account_flags & UF_DONT_EXPIRE_PASSWD:
            flags_list.append("PASSWORD_NEVER_EXPIRES")
        if account_flags & UF_PASSWORD_EXPIRED:
            flags_list.append("PASSWORD_EXPIRED")
        # Add more if desired

        return {
            "rid": rid,
            "account_flags": account_flags,
            "flags_readable": ", ".join(flags_list) if flags_list else "None",
            "last_logon": filetime_to_str(last_logon),
            "last_pwd_set": filetime_to_str(last_pwd_set),
            "account_expires": filetime_to_str(account_expires),
            "last_failed_logon": filetime_to_str(last_failed_logon),
            "failed_logon_count": failed_logon_count,
            "logon_count": logon_count,
        }

    # ------------------------------------------------------------------
    # V value parsing (username and hashes) – needs manual calibration
    # ------------------------------------------------------------------
    def parse_v_value(self, v_data):
        """
        Parse the V value to extract username and password hashes.
        The offsets below are common for many Windows 10/11 systems.
        If they don't work, use the hex dump to find the correct offsets
        and adjust them manually.
        """
        if len(v_data) < 0x24:
            return None

        # Common offsets (relative to start of V data)
        username_len = u16(v_data, 0x00)
        username_off = u16(v_data, 0x0C)
        lm_off = u16(v_data, 0x1C)
        lm_len = u16(v_data, 0x1E)
        nt_off = u16(v_data, 0x20)
        nt_len = u16(v_data, 0x22)

        username = ""
        if username_len > 0 and username_off + username_len <= len(v_data):
            username = v_data[username_off:username_off + username_len].decode("utf-16le", errors="ignore").rstrip("\x00")

        lm_blob = v_data[lm_off:lm_off + lm_len] if lm_len > 0 else b""
        nt_blob = v_data[nt_off:nt_off + nt_len] if nt_len > 0 else b""

        return {
            "username": username,
            "lm_blob": lm_blob,
            "nt_blob": nt_blob,
        }

    # ------------------------------------------------------------------
    # Main user extraction routine
    # ------------------------------------------------------------------
    def extract_users(self):
        print("\n[*] Extracting user account data from SAM\\Domains\\Account\\Users")
        users_nk = self.find_key_by_path("ROOT\\SAM\\Domains\\Account\\Users")
        if not users_nk:
            print("[-] Users key not found. Dumping all keys for manual inspection:")
            for nk in self.nk_by_abs.values():
                path = self.get_key_path(nk)
                if "Users" in path:
                    print(f"    {path} (rel=0x{nk.rel_off:08X})")
            return

        print(f"[+] Found Users key at rel=0x{users_nk.rel_off:08X}")
        child_offsets = self.parse_subkey_list(users_nk.subkey_list_rel, users_nk.subkey_count)
        print(f"[+] Found {len(child_offsets)} subkeys under Users")

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
            if not vks:
                continue

            print(f"\n[+] RID key: {nk.name} (RID {rid})")
            print(f"    Path      : {path}")
            print(f"    Timestamp : {filetime_to_str(nk.timestamp)}")
            print(f"    Values    : {len(vks)}")

            f_vk = None
            v_vk = None
            for vk in vks:
                type_name = REG_TYPES.get(vk.value_type, f"UNKNOWN({vk.value_type})")
                print(f"      VK name={vk.name!r} type={type_name} len={vk.data_len} inline={vk.inline}")
                if vk.name == "F":
                    f_vk = vk
                elif vk.name == "V":
                    v_vk = vk

            if f_vk:
                print(f"      F bytes (first 32): {f_vk.data[:32].hex()}")
                f_info = self.parse_f_value(f_vk.data)
                if f_info:
                    print(f"        RID in F           : {f_info['rid']}")
                    print(f"        Account flags      : 0x{f_info['account_flags']:08X} ({f_info['flags_readable']})")
                    print(f"        Last logon         : {f_info['last_logon']}")
                    print(f"        Last password set  : {f_info['last_pwd_set']}")
                    print(f"        Account expires    : {f_info['account_expires']}")
                    print(f"        Last failed logon  : {f_info['last_failed_logon']}")
                    print(f"        Failed logon count : {f_info['failed_logon_count']}")
                    print(f"        Logon count        : {f_info['logon_count']}")

            if v_vk:
                print(f"      V bytes (first 32): {v_vk.data[:32].hex()}")
                v_info = self.parse_v_value(v_vk.data)
                if v_info and v_info['username']:
                    print(f"        Username  : {v_info['username']}")
                    print(f"        LM blob   : {v_info['lm_blob'].hex()}")
                    print(f"        NT blob   : {v_info['nt_blob'].hex()}")
                else:
                    print("      Could not parse V value with current offsets.")
                    print("      Full V data (for manual analysis):")
                    hex_dump(v_vk.data, f"V value for {nk.name}")

    # ------------------------------------------------------------------
    # Search for interesting keys (optional)
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

        # Optional: dump a hex block for Excel mapping (e.g., first user's V value)
        # You can uncomment and adjust as needed.
        # for nk in self.nk_by_abs.values():
        #     if nk.name == "000001F4":   # Administrator
        #         vks = self.get_vk_list(nk)
        #         for vk in vks:
        #             if vk.name == "V":
        #                 hex_dump(vk.data, f"V value of {nk.name}")
        #                 break
        #         break


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