# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.
# w9 == 0x400f00
entry:
        # set the first argument of this function
        adr x6, message
        str w6, [x28, -4]!
        # w6 <- 0x4011f3 (return address)
        add w6, w9, 0x2f3
        str w6, [x28, -4]!
        # load the function address of puts
        ldr w7, [x9, 0x11b0]
        # set "puts" to the next program counter
        mov w9, w7
        bl api_call_in_cache
        br x17
message:
	.asciz "Jack in the cache!!!!!"
