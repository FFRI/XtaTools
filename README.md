# XTA Tools

In Windows 10 on ARM, we can run existing x86 applications through the x86 emulation feature.
The x86 emulation is performed through JIT binary translation from x86 to ARM64.
You might think that the JIT binary translation seems to be slow, but Microsoft have resolved this issue by providing the caching mechanism.
It reduces the much of JIT binary translation by caching binary translation result as X86-To-ARM64 (XTA) cache files.
So, when you run the same x86 applications again, JIT binary translation is not performed as long as the translated result exists in an XTA cache file.

We have presented a new code injection technique called "XTA cache hijacking" by modifying the XTA cache file at Black Hat Europe 2020.
This repository is a supplementary material for this presentation.
You can see the presentation slide [here](https://www.blackhat.com/eu-20/briefings/schedule/#jack-in-the-cache-a-new-code-injection-technique-through-modifying-x-to-arm-translation-cache-21324).

This repository contains PoC code that: 

- parses XTA cache files (via patched [radare2](https://github.com/FFRI/radare2))
- modifies some header members of XTA cache files
- injects some code into XTA cache files
- measures a function coverage of an x86 executable by analyzing an XTA cache file

# Requirements

- Python (3.8)
- poetry
- [radare2](https://github.com/FFRI/radare2)

# Installation

## Patched radare2

Firstly, you need to install patched radare2 that can parse XTA cache files.

```
$ git clone https://github.com/FFRI/radare2.git
$ cd radare2
$ git checkout xtac
$ sys/install.sh
# show some header
$ rabin2 -H USER32.DLL.B762FE91071D23DA8720F34E3667A5AB.31468294266C99D8935B35F6F76A0DF7.mp.1.jc
XTAC file header:
  magic : 0x43415458
  version : 0x1a
  is_updated : 0x0
  ptr_to_addr_pairs : 0xba30
  num_of_addr_pairs : 0x5d
  ptr_to_mod_name : 0x38
  size_of_mod_name : 0x14
  module name : USER32.DLL
  ptr_to_nt_pname : 0xbd18
  size_of_nt_pname : 0x66
  module name : \\DEVICE\\HARDDISKVOLUME3\\WINDOWS\\SYCHPE32\\USER32.DLL
  ptr_to_head_blck_stub : 0x50
  ptr_to_tail_blck_stub : 0x50
  size_of_blck_stub_code : 0xa4b0
  ptr_to_xtac_linked_list_head : 0xa534
  ptr_to_xtac_linked_list_tail : 0xb7cc
address pairs (x86, arm64):
  0x11e0, 0xa518
  0x1310, 0xa550
  0x1320, 0xa588
  0x1840, 0xa5c0
  0x1c80, 0xa5f8

(...)

blck stubs:
  blck stub entry
    ptr_to_entry : 0x50
    magic : 0x4b434c42
    offset_to_next_entry : 0xb9d0
    ptr_to_next_entry : 0x0
    padding : 0x0
xtac linked list:
  xtac linked list entry
    ptr_to_entry : 0xa534
    meta_data : 0x1
    offset_to_next_entry : 0x38
    forward_edge_addr : 0x63290
    backward_edge_addr : 0x0

(...)
```

This radare2 can be used to analyze a code in an XTA cache file.
If you are familiar with radare2 commands, you can try some commands, e.g., "iS", "iH", "i", "iSj" and get some basic information about the XTA cache file.

![radare2 Demo](./assets/radare2_xta_demo.gif)

## XTA Tools

Then, you can install XTA tools in the following manner.

```
$ git clone https://github.com/FFRI/XtaTools.git
$ cd XtaTools
$ poetry shell
$ poetry install
```

# Run examples

```
# inject code into XTA cache file
$ python -m example.inject_c2c ./example/inject_c2c_data/INJECTCODETEMPLATE.EXE.A401F5651230C64450FE6E187BD014C0.6BF6A824D8E01D39DD17A63D9204D9CB.mp.1.jc ./example/inject_c2c_data/InjectCodeTemplate.exe ./example/inject_c2c_data/TEST_X86.EXE.5B20F5225D2D28A89CBE553E4A97E5B7.EA101948E097853A1DBD8DCD3F23D197.mp.1.jc ./example/inject_c2c_data/test_x86.exe 
```

This command injects the shellcode that pops up a message box into the XTA cache file (`TEST_X86.*.*.mp.1.jc`).
By putting this XTA cache file on `%SystemRoot%\XtaCache` directry, the injected shellcode is executed as follows.

![XTA cache hijacking Demo](./assets/inject_c2c_demo.gif)

For more details and other examples, see [README](./example/README.md) of example directory.

# Tested

Windows 10 on ARM (OS Build 20221.1000)

**ATTENTION**: we haven't tested enough on Windows, whose build version is not 20221.1000.
XTA cache files created by XTA tools might not work well on a different version of Windows.

# Author

Koh M. Nakagawa. &copy; FFRI Security, Inc. 2020
