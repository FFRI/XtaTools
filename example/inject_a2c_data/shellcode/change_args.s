# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

entry:
        str w29, [x28, -4]!
        mov w29, w28
        ldr w29, [x28], 4
        adr x0, hooked
        str w0, [x28, 8]
        add w9, w9, 0xd7, lsl 12
        add w9, w9, 0xbd0
        bl api_call_in_cache
        br x17
hooked:
        .asciz "Hoooooooked!!!!!!"
