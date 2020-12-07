# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

import os
import shutil


def make_backup_file(path: str) -> None:
    print(f"make backup file of {path}")
    backup_file_name = path + ".back"
    if os.path.exists(backup_file_name):
        print(f"backup file ({backup_file_name}) already exists")
        return
    shutil.copy(path, backup_file_name)
    print(f"save the copy of {path} to {backup_file_name}")
