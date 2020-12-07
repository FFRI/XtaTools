# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

import shutil
from typing import List


def u32_to_u8_array(a: int) -> List[int]:
    return [
        a & 0xFF,
        (a >> 8) & 0xFF,
        (a >> 16) & 0xFF,
        (a >> 24) & 0xFF,
    ]


def hex_as_string(a: List[int]) -> str:
    return "".join(f"{i:02x}" for i in a)


def make_backup_file(path: str) -> None:
    print(f"make backup file of {path}")
    backup_file_name = path + ".back"
    shutil.copy(path, backup_file_name)
    print(f"save the copy of {path} to {backup_file_name}")
