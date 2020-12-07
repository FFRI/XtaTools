# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

import os
import sys
from typing import List, Optional

import lief
import r2pipe
import typer
from r2pyapi import R2Surface

from xta_tools import RelocInfo, XtaCache, XtaCacheManipulator

from .common import make_backup_file

app = typer.Typer()


def find_relocation_point(
    payload_bin: lief.ELF.Binary, reloc_name: str
) -> Optional[RelocInfo]:
    for reloc in payload_bin.relocations:
        if reloc.symbol.name == reloc_name:
            # NOTE: jmp_addr depends on XTA cache file version
            # XTA cache file version is 0x1a
            return RelocInfo(pos_rva=reloc.address, jmp_addr=0x9E68, insn="bl")
    return None


def get_code_section(
    payload_bin: lief.ELF.Binary, code_section_name: str
) -> Optional[List[int]]:
    for section in payload_bin.sections:
        if section.name == code_section_name:
            return section.content
    return None


@app.command()
def inject_a2c(
    hooking_payload_path: str,
    target_api_name: str,
    cache_dst_path: str,
    exe_dst_path: str,
) -> None:
    """
    inject API Hooking code into cache file
    """
    for path in (hooking_payload_path, cache_dst_path, exe_dst_path):
        if not os.path.exists(path):
            print(f"{path} does not exist", file=sys.stderr)
            return

    make_backup_file(cache_dst_path)

    cache_dst = XtaCache(cache_dst_path, r2_pipe_flags=["-w"])
    r2_exe_dst = r2pipe.open(exe_dst_path)
    exe_dst_surf = R2Surface(r2_exe_dst)

    if (target_api := exe_dst_surf.find_export_loose(target_api_name)) is None:
        print(f"Cannot find {target_api_name}")
        return

    target_api_rva_x86 = target_api.vaddr - exe_dst_surf.bin.baddr
    target_api_rva_arm64 = cache_dst.x86_to_arm64[target_api_rva_x86]

    print(
        f"Target is {target_api_name} (x86_rva = {hex(target_api_rva_x86)}, arm64_rva = {hex(target_api_rva_arm64)})"
    )

    # NOTE: some relocation information cannot be obtained using radare2. lief is used instead.
    hooking_payload_elf_bin = lief.ELF.parse(hooking_payload_path)
    if hooking_payload_elf_bin is None:
        print(f"{hooking_payload_path} should be ELF format")
        return

    if (
        reloc := find_relocation_point(hooking_payload_elf_bin, "api_call_in_cache")
    ) is None:
        print("Cannot find relocation point. Code is injected without relocations")
        relocs = []
    else:
        relocs = [reloc]

    if (hooking_payload := get_code_section(hooking_payload_elf_bin, ".text")) is None:
        print("Cannot find code section", file=sys.stderr)
        return

    xta_manip = XtaCacheManipulator()
    xta_manip.inject_cache_code(
        cache_dst, hooking_payload, target_api_rva_arm64, relocs
    )


if __name__ == "__main__":
    app()
