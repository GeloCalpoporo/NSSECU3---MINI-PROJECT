#!/usr/bin/env python3
import sys
import struct
from datetime import datetime, timedelta

REGF_MAGIC = b"regf"
HBIN_MAGIC = b"hbin"
NK_MAGIC = b"nk"
VK_MAGIC = b"vk"

FIRST_HBIN_ABS = 0x1000


def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def i32(data, off):
    return struct.unpack_from("<i", data, off)[0]


def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def filetime_to_str(ft):
    if ft == 0:
        return "0"
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
    if rel_off == 0xFFFFFFFF:
        return None
    return FIRST_HBIN_ABS + rel_off


class NKRecord:
    def __init__(
        self,
        abs_off,
        rel_off,
        parent_rel,
        name,
        flags,
        subkey_count,
        subkey_list_rel,
        value_count,
        value_list_rel,
        timestamp,
    ):
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


class SAMParser:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()

        self.hbins = []
        self.nks = []
        self.nk_by_rel = {}

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

        print("[*] Registry hive header")
        print(f"    Magic         : {self.data[0:4].decode(errors='ignore')}")
        print(f"    Sequence      : {seq1}:{seq2}")
        print(f"    Last write    : {filetime_to_str(last_write_ft)}")
        print(f"    Version       : {major}.{minor}")
        print(f"    Root cell rel : 0x{root_cell_rel:08X}")
        print(f"    Root cell abs : 0x{root_cell_rel + FIRST_HBIN_ABS:08X}")
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
                    self.nks.append(nk)

                cell += step

        self.nk_by_rel = {nk.rel_off: nk for nk in self.nks}
        print(f"[*] Total NK records found: {len(self.nks)}")

    def show_sample_names(self):
        print("\n[*] Sample parsed NK names")
        for nk in self.nks[:40]:
            print(f"    rel=0x{nk.rel_off:08X}  name={repr(nk.name)}")

    def get_path(self, nk):
        parts = []
        seen = set()
        cur = nk

        while cur is not None:
            if cur.rel_off in seen:
                break
            seen.add(cur.rel_off)

            parts.append(cur.name)

            if cur.parent_rel == 0xFFFFFFFF or cur.parent_rel not in self.nk_by_rel:
                break

            parent = self.nk_by_rel.get(cur.parent_rel)
            if parent is None or parent == cur:
                break
            cur = parent

        parts.reverse()
        return "\\".join(parts)

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

    def get_vk_list_for_nk(self, nk):
        vks = []

        if nk.value_count == 0 or nk.value_list_rel in (0, 0xFFFFFFFF):
            return vks

        value_list_abs = rel_to_abs(nk.value_list_rel)
        if value_list_abs is None:
            return vks

        for i in range(nk.value_count):
            entry_off = value_list_abs + (i * 4)
            if entry_off + 4 > len(self.data):
                break

            vk_rel = u32(self.data, entry_off)
            if vk_rel == 0xFFFFFFFF:
                continue

            vk_abs = rel_to_abs(vk_rel)
            if vk_abs is None or vk_abs + 4 > len(self.data):
                continue

            vk = self.parse_vk(vk_abs)
            if vk:
                vks.append(vk)

        return vks

    def parse_user_v_value(self, vdata):
        """
        Parse the V value using common Windows SAM offsets.
        Offsets (all relative to start of V data):
        0x00: username length (2 bytes)
        0x0C: username offset (2 bytes)
        0x1C: LM hash offset (2 bytes)
        0x1E: LM hash length (2 bytes)
        0x20: NT hash offset (2 bytes)
        0x22: NT hash length (2 bytes)
        The username is UTF-16LE at offset.
        Full name and comment are optional; we can add them later.
        """
        if len(vdata) < 0x24:
            return None

        username_len = u16(vdata, 0x00)
        username_off = u16(vdata, 0x0C)
        lm_off = u16(vdata, 0x1C)
        lm_len = u16(vdata, 0x1E)
        nt_off = u16(vdata, 0x20)
        nt_len = u16(vdata, 0x22)

        username = ""
        if username_len > 0 and username_off + username_len <= len(vdata):
            username = vdata[username_off:username_off+username_len].decode("utf-16le", errors="ignore").rstrip("\x00")

        lm_blob = vdata[lm_off:lm_off+lm_len] if lm_len > 0 else b""
        nt_blob = vdata[nt_off:nt_off+nt_len] if nt_len > 0 else b""

        return {
            "username": username,
            "full_name": "",
            "comment": "",
            "lm_blob": lm_blob,
            "nt_blob": nt_blob,
        }

    def show_structure_hits(self):
        print("\n[*] Reconstructed key paths of interest")

        interesting = []
        for nk in self.nks:
            path = self.get_path(nk)
            if (
                path.endswith("SAM\\Domains\\Account")
                or path.endswith("SAM\\Domains\\Account\\Users")
                or path.endswith("SAM\\Domains\\Account\\Users\\Names")
                or path.endswith("SAM\\Domains\\Builtin")
            ):
                interesting.append((path, nk))

        if not interesting:
            print("    No exact reconstructed paths found.")
            return

        for path, nk in interesting:
            print(
                f"    {path}  "
                f"(rel=0x{nk.rel_off:08X}, subkeys={nk.subkey_count}, values={nk.value_count})"
            )

    def extract_user_accounts(self):
        print("\n[*] Extracting user account data from RID-style keys")

        found_any = False

        for nk in self.nks:
            if len(nk.name) != 8:
                continue

            try:
                rid = int(nk.name, 16)
            except ValueError:
                continue

            path = self.get_path(nk)
            if "SAM\\Domains\\Account\\Users" not in path:
                continue

            vks = self.get_vk_list_for_nk(nk)
            if not vks:
                continue

            found_any = True
            print(f"\n[+] RID key: {nk.name} (RID {rid})")
            print(f"    Path      : {path}")
            print(f"    Timestamp : {filetime_to_str(nk.timestamp)}")
            print(f"    Values    : {len(vks)}")

            f_vk = None
            v_vk = None

            for vk in vks:
                shown_name = vk.name if vk.name else "(default)"
                print(
                    f"      VK name={shown_name!r} "
                    f"type={vk.value_type} len={vk.data_len} inline={vk.inline}"
                )
                if vk.name == "F":
                    f_vk = vk
                elif vk.name == "V":
                    v_vk = vk

            if f_vk:
                print(f"      F bytes (first 32): {f_vk.data[:32].hex()}")

            if v_vk:
                parsed_v = self.parse_user_v_value(v_vk.data)
                print(f"      V bytes (first 32): {v_vk.data[:32].hex()}")

                if parsed_v:
                    print(f"      Username  : {parsed_v['username']}")
                    if parsed_v["full_name"]:
                        print(f"      Full name : {parsed_v['full_name']}")
                    if parsed_v["comment"]:
                        print(f"      Comment   : {parsed_v['comment']}")

                    if parsed_v["lm_blob"]:
                        print(f"      LM blob   : {parsed_v['lm_blob'].hex()}")
                    else:
                        print("      LM blob   : <empty>")

                    if parsed_v["nt_blob"]:
                        print(f"      NT blob   : {parsed_v['nt_blob'].hex()}")
                    else:
                        print("      NT blob   : <empty>")
                else:
                    print("      Could not parse V structure with current offsets.")
                    print("      Full V data hex (for manual analysis):")
                    # Print in 16-byte rows for readability
                    for i in range(0, len(v_vk.data), 16):
                        chunk = v_vk.data[i:i+16]
                        hex_part = ' '.join(f'{b:02x}' for b in chunk)
                        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                        print(f"        {i:04x}: {hex_part:<47} {ascii_part}")
                    print("      Use this to locate the username (as UTF-16LE) and hashes.")
                    print("      Then adjust offsets in parse_user_v_value().")

        if not found_any:
            print("    No RID-style account keys with readable values were extracted.")
            print("    This can still happen if some offsets differ across versions.")
            print("    Use HxD + Excel to verify F and V manually.")

    def search_interesting(self):
        print("\n[*] Searching for interesting names directly")

        exact_targets = {
            "SAM", "Domains", "Account", "Users", "Names",
            "Administrator", "Guest", "DefaultAccount"
        }

        found_exact = []
        found_rids = []
        found_probable_users = []

        for nk in self.nks:
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
                    found_probable_users.append(nk)

        print("\n[+] Exact target names found")
        if found_exact:
            for nk in found_exact:
                print(
                    f"    name={nk.name} rel=0x{nk.rel_off:08X} "
                    f"parent=0x{nk.parent_rel:08X} subkeys={nk.subkey_count} values={nk.value_count}"
                )
        else:
            print("    None")

        print("\n[+] RID-style keys found")
        if found_rids:
            for nk, rid in found_rids:
                print(
                    f"    name={nk.name} RID={rid} rel=0x{nk.rel_off:08X} "
                    f"parent=0x{nk.parent_rel:08X} values={nk.value_count}"
                )
        else:
            print("    None")

        print("\n[+] Likely user/group names")
        seen = set()
        count = 0
        for nk in found_probable_users:
            if nk.name in seen:
                continue
            seen.add(nk.name)
            print(f"    {nk.name}")
            count += 1
            if count >= 80:
                break

    def run(self):
        self.parse_header()
        self.parse_hbins()
        self.scan_nks()
        self.show_sample_names()
        self.search_interesting()
        self.show_structure_hits()
        self.extract_user_accounts()


def main():
    if len(sys.argv) != 2:
        print("Usage: py sam_parser.py SAM_copy")
        sys.exit(1)

    parser = SAMParser(sys.argv[1])
    parser.run()


if __name__ == "__main__":
    main()