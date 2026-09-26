"""Extract a narrow offline kernel profile from a PE and matching public PDB.

Requires llvm-pdbutil on PATH. Does not download files, inspect running processes,
or infer a capture's kernel base or page-table root. Raw inputs stay caller-owned.
"""

import argparse
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import uuid


def one(pattern, text):
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"Expected one match for {pattern!r}, found {len(matches)}")
    return matches[0]


def pe_identity(path):
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Not a PE image")
    machine, count, timestamp = struct.unpack_from("<HHI", data, pe + 4)
    optional_bytes = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    if machine != 0x8664 or struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError("Only AMD64 PE32+ images are supported")
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    image_bytes, headers_bytes, checksum = struct.unpack_from("<III", data, optional + 56)
    sections = []
    for index in range(count):
        offset = optional + optional_bytes + index * 40
        name, virtual_bytes, rva, raw_bytes, raw_offset = struct.unpack_from("<8sIIII", data, offset)
        sections.append({"number": index + 1, "name": name.rstrip(b"\0").decode("ascii"),
                         "rva": rva, "virtual_bytes": virtual_bytes,
                         "raw_bytes": raw_bytes, "raw_offset": raw_offset})

    def file_offset(rva, length):
        if rva + length <= headers_bytes:
            return rva
        for section in sections:
            delta = rva - section["rva"]
            if 0 <= delta and delta + length <= section["raw_bytes"]:
                return section["raw_offset"] + delta
        raise ValueError("Debug directory is outside initialized image bytes")

    debug_rva, debug_bytes = struct.unpack_from("<II", data, optional + 112 + 6 * 8)
    if debug_bytes % 28:
        raise ValueError("Unexpected debug directory size")
    records = []
    for delta in range(0, debug_bytes, 28):
        offset = file_offset(debug_rva + delta, 28)
        kind, length, _, raw_offset = struct.unpack_from("<IIII", data, offset + 12)
        if kind != 2:
            continue
        record = data[raw_offset:raw_offset + length]
        if len(record) != length or record[:4] != b"RSDS":
            raise ValueError("Unsupported or truncated CodeView record")
        records.append({"guid": str(uuid.UUID(bytes_le=record[4:20])).upper(),
                        "age": struct.unpack_from("<I", record, 20)[0],
                        "name": record[24:].split(b"\0", 1)[0].decode("utf-8")})
    if len(records) != 1:
        raise ValueError("Expected exactly one RSDS record")
    return {"name": path.name, "sha256": hashlib.sha256(data).hexdigest(),
            "file_bytes": len(data), "machine": machine, "timestamp": timestamp,
            "preferred_image_base": image_base, "image_bytes": image_bytes,
            "checksum": checksum, "codeview": records[0]}, sections


def extract(image_path, pdb_path, llvm):
    def run(*arguments):
        return subprocess.check_output([llvm, *arguments], text=True, encoding="utf-8")

    image, sections = pe_identity(image_path)
    streams = run("pdb2yaml", "--pdb-stream", "--dbi-stream", str(pdb_path))
    info = streams.split("PdbStream:", 1)[1].split("DbiStream:", 1)[0]
    dbi = streams.split("DbiStream:", 1)[1]
    guid = one(r"^\s+Guid:\s+'\{([^}]+)\}'", info).upper()
    info_age = int(one(r"^\s+Age:\s+(\d+)", info))
    dbi_age = int(one(r"^\s+Age:\s+(\d+)", dbi))
    flags = int(one(r"^\s+Flags:\s+(\d+)", dbi))
    image_age = image["codeview"]["age"]
    if guid != image["codeview"]["guid"] or info_age < image_age or dbi_age != image_age:
        raise ValueError("PDB does not match PE GUID and age validation rules")
    if flags & 2 == 0:
        raise ValueError("Expected a public PDB with private symbols stripped")

    types = run("dump", "--types", str(pdb_path))
    records = dict(re.findall(r"^\s+(0x[0-9A-F]+) \| (.*?)(?=^\s+0x[0-9A-F]+ \| |\Z)",
                              types, re.MULTILINE | re.DOTALL))
    evidence = {}

    def structure(name):
        candidates = [(index, record) for index, record in records.items()
                      if re.match(r"LF_STRUCTURE .* `" + re.escape(name) + r"`\n", record)
                      and "forward ref" not in record]
        if len(candidates) != 1:
            raise ValueError(f"Ambiguous full structure {name}")
        index, record = candidates[0]
        field_index = one(r"field list: (0x[0-9A-F]+)", record)
        evidence[index] = record.rstrip()
        evidence[field_index] = records[field_index].splitlines()[0]
        return {"type_index": index, "field_list": field_index,
                "bytes": int(one(r"sizeof (\d+)", record))}

    eprocess = structure("_EPROCESS")
    kprocess = structure("_KPROCESS")
    list_entry = structure("_LIST_ENTRY")
    audit = structure("_SE_AUDIT_PROCESS_CREATION_INFO")
    name_info = structure("_OBJECT_NAME_INFORMATION")
    unicode = structure("_UNICODE_STRING")

    def member(structure_record, name):
        record = records[structure_record["field_list"]]
        pattern = (r"LF_MEMBER \[name = `" + re.escape(name) +
                   r"`, Type = (0x[0-9A-Fa-f]+).*?, offset = (\d+),")
        type_index, offset = one(pattern, record)
        evidence[structure_record["field_list"]] += "\n" + next(
            line for line in record.splitlines() if re.search(pattern, line))
        if type_index in records:
            evidence[type_index] = records[type_index].rstrip()
            forward = re.search(r"forward ref \(-> (0x[0-9A-F]+)\)", records[type_index])
            if forward:
                evidence[forward[1]] = records[forward[1]].rstrip()
        return {"offset": int(offset), "type_index": type_index}

    fields = {name: member(eprocess, name) for name in
              ("Pcb", "UniqueProcessId", "ActiveProcessLinks", "CreateTime", "ImageFileName",
               "Peb", "WoW64Process", "SeAuditProcessCreationInfo")}
    for name in ("DirectoryTableBase", "UserDirectoryTableBase"):
        field = member(kprocess, name)
        field["eprocess_offset"] = fields["Pcb"]["offset"] + field["offset"]
        fields["Pcb." + name] = field
    field = member(audit, "ImageFileName")
    field["eprocess_offset"] = fields["SeAuditProcessCreationInfo"]["offset"] + field["offset"]
    fields["SeAuditProcessCreationInfo.ImageFileName"] = field
    image_name_type = fields["ImageFileName"]["type_index"]
    evidence[image_name_type] = records[image_name_type].rstrip()
    fields["ImageFileName"]["bytes"] = int(one(r"size: (\d+),", records[image_name_type]))
    list_fields = {name: member(list_entry, name) for name in ("Flink", "Blink")}
    name_fields = {"Name": member(name_info, "Name")}
    string_fields = {name: member(unicode, name) for name in ("Length", "Buffer")}

    publics = run("dump", "--publics", str(pdb_path))
    symbols = {}
    for name in ("PsActiveProcessHead", "PsInitialSystemProcess", "KiSystemCall64", "KiSystemCall64Shadow"):
        record, section_number, offset = one(
            r"(^\s+\d+ \| S_PUB32 .* `" + name +
            r"`\n\s+flags = [^\n]*?, addr = (\d+):(\d+))", publics)
        if not 1 <= int(section_number) <= len(sections):
            raise ValueError("Symbol has an invalid section number")
        section = sections[int(section_number) - 1]
        offset = int(offset)
        if offset >= section["virtual_bytes"] or section["rva"] + offset >= image["image_bytes"]:
            raise ValueError("Symbol exceeds section or image size")
        symbols[name] = {"section": int(section_number), "section_name": section["name"],
                         "section_rva": section["rva"], "section_offset": offset,
                         "rva": section["rva"] + offset, "record": record.strip()}
    return {"schema_version": 1, "scope": "offline supplied-memory images; static evidence only",
            "image": image,
            "pdb": {"name": pdb_path.name, "guid": guid, "info_age": info_age,
                    "dbi_age": dbi_age, "private_symbols_stripped": True,
                    "file_bytes": pdb_path.stat().st_size,
                    "sha256": hashlib.sha256(pdb_path.read_bytes()).hexdigest(),
                    "url": "https://msdl.microsoft.com/download/symbols/" +
                           image["codeview"]["name"] + "/" + guid.replace("-", "") +
                           format(image_age, "X") + "/" + image["codeview"]["name"]},
            "types": {"_EPROCESS": eprocess, "_KPROCESS": kprocess, "_LIST_ENTRY": list_entry,
                      "_SE_AUDIT_PROCESS_CREATION_INFO": audit,
                      "_OBJECT_NAME_INFORMATION": name_info, "_UNICODE_STRING": unicode},
            "fields": fields, "list_fields": list_fields, "name_fields": name_fields,
            "string_fields": string_fields, "symbols": symbols,
            "llvm_version": run("--version").strip(), "type_evidence": evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=pathlib.Path, required=True)
    parser.add_argument("--pdb", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--llvm-pdbutil", default="llvm-pdbutil")
    arguments = parser.parse_args()
    result = extract(arguments.image, arguments.pdb, arguments.llvm_pdbutil)
    arguments.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
