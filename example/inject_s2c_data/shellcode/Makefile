all: shellcode.bin

shellcode.out: shellcode.s
	aarch64-linux-gnu-as $< -o $@

shellcode.bin: shellcode.out
	aarch64-linux-gnu-objcopy --output-format=binary $< $@

clean:
	rm shellcode.bin shellcode.out
