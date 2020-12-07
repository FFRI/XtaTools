# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

import os
import sys
from typing import Dict

import r2pipe
import typer
from r2pyapi import R2Function, R2Surface

from xta_tools import XtaCache

from .drcov_exporter import BasicBlock, CoverageInfo, export_as_drcov_format

app = typer.Typer()


# Not implemented yet
# @app.command()
# def show_code_coverage(cache_path: str, x86_exe_path: str, output_path: str) -> None:
#     print("show code coverage")
#     for path in (cache_path, x86_exe_path):
#         if not os.path.exists(path):
#             print(f"{path} is not found", file=sys.stderr)
#             return
#
#     xta_cache = XtaCache(cache_path)
#     r2_x86_exe = r2pipe.open(x86_exe_path)
#     x86_exe_surf = R2Surface(r2_x86_exe)


@app.command()
def show_function_coverage(
    cache_path: str, x86_exe_path: str, output_path: str
) -> None:
    print("show function coverage")
    for path in (cache_path, x86_exe_path):
        if not os.path.exists(path):
            print(f"{path} is not found", file=sys.stderr)
            return

    xta_cache = XtaCache(cache_path)
    r2_x86_exe = r2pipe.open(x86_exe_path)
    x86_exe_surf = R2Surface(r2_x86_exe)

    rva_to_func: Dict[int, R2Function] = {
        func.offset - x86_exe_surf.bin.baddr: func for func in x86_exe_surf.functions
    }

    passed_blocks = [
        BasicBlock(
            passed_rva=address_pair.rva_x86,
            passed_size=rva_to_func[address_pair.rva_x86].size,
        )
        for address_pair in xta_cache.address_pairs
        if address_pair.rva_x86 in rva_to_func.keys()
    ]

    cov_info = CoverageInfo(
        name=x86_exe_surf.core.file,
        base_addr=x86_exe_surf.bin.baddr,
        module_size=x86_exe_surf.core.size,
        passed_blocks=passed_blocks,
    )

    print(f"save function coverage information to {output_path}")
    export_as_drcov_format(output_path, [cov_info])

    print("print passed functions")
    for address_pair in xta_cache.address_pairs:
        if address_pair.rva_x86 in rva_to_func.keys():
            print(rva_to_func[address_pair.rva_x86].name)


if __name__ == "__main__":
    app()
