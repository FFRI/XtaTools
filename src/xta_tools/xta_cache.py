# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Union, cast

import r2pipe

from .utils import hex_as_string, u32_to_u8_array


@dataclass
class AddressPair:
    rva_x86: int
    rva_arm64: int

    def __str__(self) -> str:
        return f"(x86: {hex(self.rva_x86)}, arm64: {hex(self.rva_arm64)})"

    def __repr__(self) -> str:
        return (
            f"AddressPair(rva_arm64={hex(self.rva_arm64)}, rva_x86={hex(self.rva_x86)})"
        )

    def __add__(self, other: "AddressPair") -> "AddressPair":
        return AddressPair(
            rva_x86=self.rva_x86 + other.rva_x86,
            rva_arm64=self.rva_arm64 + other.rva_arm64,
        )

    def as_hex_str(self) -> str:
        return hex_as_string(
            u32_to_u8_array(self.rva_x86) + u32_to_u8_array(self.rva_arm64)
        )


@dataclass
class BlckStub:
    magic: int
    offset_to_next_entry: int
    ptr_to_next_entry: int
    padding: int
    ptr_to_entry: int

    def __str__(self) -> str:
        return f"(magic: {hex(self.magic)}, offset_to_next_entry: {hex(self.offset_to_next_entry)}, ptr_to_next_entry: {hex(self.ptr_to_next_entry)}, padding: {hex(self.padding)}, ptr_to_entry: {hex(self.padding)})"

    def __repr__(self) -> str:
        return f"BlckStub(magic={hex(self.magic)}, offset_to_next_entry={hex(self.offset_to_next_entry)}, ptr_to_next_entry={hex(self.ptr_to_next_entry)}, padding={hex(self.padding)}, ptr_to_entry={hex(self.padding)})"


@dataclass
class XtacLinkedListEntry:
    meta_and_offset: int
    forward_edge_addr: Optional[int]
    backward_edge_addr: Optional[int]
    ptr_to_entry: int

    @staticmethod
    def print_optional(v: Optional[int]) -> str:
        return hex(v) if v else "N/A"

    def __str__(self) -> str:
        return f"(meta_and_offset: {hex(self.meta_and_offset)}, forward_edge_addr: {self.print_optional(self.forward_edge_addr)}, backward_edge_addr: {self.print_optional(self.backward_edge_addr)}, ptr_to_entry: {hex(self.ptr_to_entry)})"

    def __repr__(self) -> str:
        return f"XtacLinkedListEntry(meta_and_offset={hex(self.meta_and_offset)}, forward_edge_addr={self.print_optional(self.forward_edge_addr)}, backward_edge_addr={self.print_optional(self.backward_edge_addr)}, ptr_to_entry={hex(self.ptr_to_entry)})"


RBinField = Dict[str, Union[str, int, List[Dict[str, Union[str, int]]]]]
RBinFields = List[RBinField]


def _get_value_from_rbin_field(entry: RBinField) -> Union[str, int]:
    if entry["format"] == "x":
        return int(cast(str, entry["comment"]), 16)
    else:
        return cast(str, entry["comment"])


@dataclass(init=False)
class XtaCacheHeader:
    magic: int
    version: int
    is_updated: int
    ptr_to_addr_pairs: int
    num_of_addr_pairs: int
    ptr_to_mod_name: int
    size_of_mod_name: int
    mod_name: str
    ptr_to_nt_pname: int
    size_of_nt_pname: int
    nt_pname: str
    ptr_to_head_blck_stub: int
    ptr_to_tail_blck_stub: int
    size_of_blck_stub_code: int
    ptr_to_xtac_linked_list_head: int
    ptr_to_xtac_linked_list_tail: int

    def read_from_rbin_field(self, entry: RBinField) -> None:
        if entry["name"] == "magic":
            self.magic = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "version":
            self.version = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "is_updated":
            self.is_updated = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "ptr_to_addr_pairs":
            self.ptr_to_addr_pairs = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "num_of_addr_pairs":
            self.num_of_addr_pairs = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "ptr_to_mod_name":
            self.ptr_to_mod_name = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "size_of_mod_name":
            self.size_of_mod_name = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "mod_name":
            self.mod_name = cast(str, _get_value_from_rbin_field(entry))
        elif entry["name"] == "ptr_to_nt_pname":
            self.ptr_to_nt_pname = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "size_of_nt_pname":
            self.size_of_nt_pname = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "nt_pname":
            self.nt_pname = cast(str, _get_value_from_rbin_field(entry))
        elif entry["name"] == "ptr_to_head_blck_stub":
            self.ptr_to_head_blck_stub = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "ptr_to_tail_blck_stub":
            self.ptr_to_tail_blck_stub = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "size_of_blck_stub_code":
            self.size_of_blck_stub_code = cast(int, _get_value_from_rbin_field(entry))
        elif entry["name"] == "ptr_to_xtac_linked_list_head":
            self.ptr_to_xtac_linked_list_head = cast(
                int, _get_value_from_rbin_field(entry)
            )
        elif entry["name"] == "ptr_to_xtac_linked_list_tail":
            self.ptr_to_xtac_linked_list_tail = cast(
                int, _get_value_from_rbin_field(entry)
            )


class XtaCache:
    def __str__(self) -> str:
        xta_cache_header_str = str(self.xta_cache_header)
        address_pairs_str = "\n".join(
            str(address_pair) for address_pair in self.address_pairs
        )
        blck_stubs_str = "\n".join(str(blck_stub) for blck_stub in self.blck_stubs)
        xtac_linked_list_str = "\n".join(str(entry) for entry in self.xtac_linked_list)
        return "\n".join(
            [
                xta_cache_header_str,
                address_pairs_str,
                blck_stubs_str,
                xtac_linked_list_str,
            ]
        )

    @staticmethod
    def process_address_pairs(address_pairs_raw: RBinFields) -> List[AddressPair]:
        return [
            AddressPair(
                cast(int, _get_value_from_rbin_field(x86)),
                cast(int, _get_value_from_rbin_field(arm64)),
            )
            for x86, arm64 in zip(address_pairs_raw[0::2], address_pairs_raw[1::2])
        ]

    @staticmethod
    def process_blck_stubs(blck_stubs_raw: RBinFields) -> List[BlckStub]:
        return [
            BlckStub(
                magic=cast(int, _get_value_from_rbin_field(magic)),
                offset_to_next_entry=cast(
                    int, _get_value_from_rbin_field(offset_to_next_entry)
                ),
                ptr_to_next_entry=cast(
                    int, _get_value_from_rbin_field(ptr_to_next_entry)
                ),
                padding=cast(int, _get_value_from_rbin_field(padding)),
                ptr_to_entry=cast(int, magic["vaddr"]),
            )
            for magic, offset_to_next_entry, ptr_to_next_entry, padding in zip(
                blck_stubs_raw[0::4],
                blck_stubs_raw[1::4],
                blck_stubs_raw[2::4],
                blck_stubs_raw[3::4],
            )
        ]

    @staticmethod
    def has_forward_edge_addr(meta_and_offset: int) -> bool:
        return (meta_and_offset & 0x10000000) == 0x10000000

    @staticmethod
    def has_backward_edge_addr(meta_and_offset: int) -> bool:
        return (meta_and_offset & 0x20000000) == 0x20000000

    @staticmethod
    def process_xtac_linked_list(
        xtac_linked_list_raw: RBinFields,
    ) -> List[XtacLinkedListEntry]:
        xtac_linked_list: List[XtacLinkedListEntry] = list()
        i = 0
        length = len(xtac_linked_list_raw)
        while i < length:
            meta_and_offset = cast(
                int, _get_value_from_rbin_field(xtac_linked_list_raw[i])
            )
            ptr_to_entry = cast(int, xtac_linked_list_raw[i]["vaddr"])
            i += 1
            forward_edge_addr = None
            backward_edge_addr = None
            if XtaCache.has_forward_edge_addr(meta_and_offset):
                forward_edge_addr = cast(
                    int, _get_value_from_rbin_field(xtac_linked_list_raw[i])
                )
                i += 1
            if XtaCache.has_backward_edge_addr(meta_and_offset):
                backward_edge_addr = cast(
                    int, _get_value_from_rbin_field(xtac_linked_list_raw[i])
                )
                i += 1
            xtac_linked_list.append(
                XtacLinkedListEntry(
                    meta_and_offset, forward_edge_addr, backward_edge_addr, ptr_to_entry
                )
            )
        return xtac_linked_list

    @staticmethod
    def r2_supports_xtac(r2_cache: r2pipe.open_sync.open) -> bool:
        if r2_cache.cmdj("ij")["core"]["type"] != "XTAC":
            print(
                "Please use patched version radare2 to parse XTA cache file",
                file=sys.stderr,
            )
            return False
        return True

    def __init__(
        self, cache_name: str, r2_pipe_flags: Optional[List[str]] = None
    ) -> None:
        r2_pipe_flags = [] if r2_pipe_flags is None else r2_pipe_flags
        self.r2_cache = r2pipe.open(cache_name, flags=r2_pipe_flags)
        if not self.r2_supports_xtac(self.r2_cache):
            return

        self.xta_cache_header = XtaCacheHeader()

        address_pairs_raw = list()
        blck_stubs_raw = list()
        xtac_linked_list_raw = list()
        for entry in self.r2_cache.cmdj("iHj"):
            self.xta_cache_header.read_from_rbin_field(entry)
            if entry["name"].startswith("address_pairs["):
                address_pairs_raw.append(entry)
            elif entry["name"].startswith("blck_stub["):
                blck_stubs_raw.append(entry)
            elif entry["name"].startswith("xtac_linked_list["):
                xtac_linked_list_raw.append(entry)

        self.address_pairs = self.process_address_pairs(address_pairs_raw)
        self.blck_stubs = self.process_blck_stubs(blck_stubs_raw)
        self.xtac_linked_list = self.process_xtac_linked_list(xtac_linked_list_raw)

        self.x86_to_arm64: Dict[int, int] = {
            pair.rva_x86: pair.rva_arm64 for pair in self.address_pairs
        }
        self.arm64_to_x86: Dict[int, int] = {
            pair.rva_arm64: pair.rva_x86 for pair in self.address_pairs
        }
