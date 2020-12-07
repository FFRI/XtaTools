# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

import io
from ctypes import Structure, c_uint16, c_uint32
from dataclasses import dataclass
from typing import BinaryIO, Dict, List

"""
{
    "name": "test.exe",
    "base_addr": 0x400000,
    "size": 0x6000,
    "passed_blocks": [(0x1000, 0x6), (0x1020, 0x2), ...]
}
"""


@dataclass
class BasicBlock:
    passed_rva: int
    passed_size: int


@dataclass
class CoverageInfo:
    name: str
    base_addr: int
    module_size: int
    passed_blocks: List[BasicBlock]


def export_as_drcov_format(file_name: str, cov_infos: List[CoverageInfo]) -> None:
    with open(file_name, "wb") as fout:
        _write_header(fout)
        _write_module_table(fout, cov_infos)
        _write_bb_table(fout, cov_infos)


def _write_header(fout: BinaryIO) -> None:
    fout.write(b"DRCOV VERSION: 2\n")
    fout.write(b"DRCOV FLAVOR: drcov\n")


def _write_module_table(fout: BinaryIO, cov_infos: List[CoverageInfo]) -> None:
    _write_module_table_header(fout, len(cov_infos))
    for idx, cov_info in enumerate(cov_infos):
        _write_module_table_entry(fout, idx, cov_info)


def _write_module_table_header(fout: BinaryIO, count: int) -> None:
    fout.write(f"Module Table: version 2, count {count}\n".encode("utf-8"))
    fout.write(b"Columns: id, base, end, entry, checksum, timestamp, path\n")


def _write_module_table_entry(fout: BinaryIO, idx: int, cov_info: CoverageInfo) -> None:
    fout.write(
        f"{idx}, {hex(cov_info.base_addr)}, {hex(cov_info.base_addr + cov_info.module_size)}, 0x0000000000000000, 0x00000000, 0x00000000, {cov_info.name}\n".encode(
            "utf-8"
        )
    )


def _write_bb_table(fout: BinaryIO, cov_infos: List[CoverageInfo]) -> None:
    _write_bb_table_header(
        fout, sum(len(cov_info.passed_blocks) for cov_info in cov_infos)
    )

    for idx, cov_info in enumerate(cov_infos):
        for passed_block in cov_info.passed_blocks:
            _write_bb_table_entry(
                fout, passed_block.passed_rva, passed_block.passed_size, idx
            )


def _write_bb_table_header(fout: BinaryIO, count: int) -> None:
    fout.write(f"BB Table: {count} bbs\n".encode("utf-8"))


"""
// See https://www.ayrx.me/drcov-file-format
typedef struct _bb_entry_t {
    uint   start;      /* offset of bb start from the image base */
    ushort size;
    ushort mod_id;
} bb_entry_t;
"""


class BBEntry(Structure):
    _fields_ = (("start", c_uint32), ("size", c_uint16), ("mod_id", c_uint16))


def _write_bb_table_entry(
    fout: BinaryIO, start_rva: int, bb_size: int, mod_id: int
) -> None:
    buffer_ = io.BytesIO()
    buffer_.write(bytearray(BBEntry(start_rva, bb_size, mod_id)))
    fout.write(buffer_.getvalue())
