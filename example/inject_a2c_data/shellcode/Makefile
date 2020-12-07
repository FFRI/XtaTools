all: change_args.bin

change_args.out: change_args.s
	aarch64-linux-gnu-as $< -o $@

change_args.bin: change_args.out
	aarch64-linux-gnu-objcopy --output-format=binary $< $@

clean:
	rm change_args.bin change_args.out
