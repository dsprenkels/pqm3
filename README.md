# PQM3

PQM3 contains _post quantum_ crypto schemes to the _Cortex M3_.

We target any scheme that is a finalist or alternate third round candidate in the [NIST competition](https://csrc.nist.gov/news/2020/pqc-third-round-candidate-announcement).
Our goal is to show which schemes are feasible for deployment om Cortex M3
devices, and show how they compare in speed and size.

This project is based on its sister project [`pqm4`](https://github.com/mupq/pqm4) and builds upon [`mupq`](https://github.com/mupq/mupq) and [`PQClean`](https://github.com/PQClean/PQClean)

## Getting started

We currently support multiple boards, but also support the schemes to be
emulated using QEMU. Let me get you up to speed:

```shell
# Clone the repository and cd into it.
git clone --recursive https://github.com/mupq/pqm3.git
cd pqm3

# Install all the required dependencies.
# Arch linux
sudo pacman -S arm-none-eabi-gcc arm-none-eabi-binutils qemu qemu-arch-extra

# Ubuntu
sudo apt install gcc-arm-none-eabi binutils-arm-none-eabi qemu-system-arm

# QEMU emulates the lm3s platform. So build all the schemes with `PLATFORM=lm3s`.
make -j PLATFORM=lm3s

# At this point there is a bunch of binaries in the `elf/` directory.
# You can run any of these binaries using `qemu-system-arm`. For example, to
# test kyber768, run:
qemu-system-arm -cpu cortex-m3 \
                -machine lm3s6965evb \
                -nographic \
                -semihosting-config enable=on,target=native \
                -kernel ./elf/crypto_kem_kyber768_m3_test.elf

# To kill the qemu emulator, press Ctrl+A and then X.
```

## Running on hardware

We currently support the following platforms:

- `lm3s`: The board emulated by QEMU (default).
- `sam3x8e`: The [Arduino Due](https://store.arduino.cc/arduino-due) development board.
- `nucleo-f207zg`: The [Nucleo STM32F207ZG](https://www.st.com/en/evaluation-tools/nucleo-f207zg.html).
<!-- This next link was broken on the ST website? Had the board been discontinued? -->
- `stm32l100c-disco`: The [STM32L100 Discovery board](https://web.archive.org/web/20200902192134/https://www.st.com/en/evaluation-tools/32l100cdiscovery.html).
  (See [#2](https://github.com/mupq/pqm3/pull/2))

### Arduino Due

For flashing the firmwares to the Arduino Due, we use the [Bossa](https://www.shumatech.com/web/products/bossa) tool.
We will use the `miniterm` serial monitor to read the output from the Arduino.

First, to compile for the Arduino Due, set the `PLATFORM` variable to `sam3x8e`.

The Arduino Due binaries are written to `bin/`, but are not built by default.
So you will have to tell `make` what you want.
For example, to produce a speed benchmark of Kyber768, plug in your Due and run:

```shell
make PLATFORM=sam3x8e ./bin/crypto_kem_kyber768_m3_speed.bin
# (You might need to run `make clean` first, if you previously built for a different platform.)

# Flash the binary using bossac.
bossac -a --erase --write --verify --boot=1 --port=/dev/ttyACM0 ./bin/crypto_kem_kyber768_m3_speed.bin

# Open the serial monitor.
miniterm.py /dev/ttyACM0

```

If everything went well, you should have gotten something looking like this:

```
--- Miniterm on /dev/ttyACM0  9600,8,N,1 ---
--- Quit: Ctrl+] | Menu: Ctrl+T | Help: Ctrl+T followed by Ctrl+H ---
==========================
keypair cycles:
1087702
encaps cycles:
1281392
decaps cycles:
1228259
OK KEYS
```

### Nucleo-F207ZG

For flashing the firmwares to the Nucleo-F207ZG board, you will need an up to date GIT version of [OpenOCD](http://openocd.org/) (we tested with commit `9a877a83a1c8b1f105cdc0de46c5cbc4d9e8799e`).
You may also need to [update the firmware](https://www.st.com/en/development-tools/stsw-link007.html) of the STLINK/v2-1 probe (we tested with version `V2J37M26`).
The [stlink](https://github.com/stlink-org/stlink) tool may also work, depending on the firmware version of your STLINK/v2-1 probe.
We use OpenOCD, as the `stlink` tool caused problems on our board.

To compile code for this board, pass the `PLATFORM=nucleo-f207zg` variable to make.
Then you can either flash the ELF or BIN files to your board using OpenOCD.

```shell
make PLATFORM=nucleo-f207zg -j4
openocd -f nucleo-f2.cfg -c "program elf/crypto_kem_kyber768_m3_speed.bin reset exit"
```

Alternatively, you could also debug the code using OpenOCD as a GDB server.

```shell
# Start the GDB Server (in another shell)
openocd -f nucleo-f2.cfg # This starts the GDB server
# Start GDB and...
arm-none-eabi-gdb -ex "target remote :3333" elf/crypto_kem_kyber768_m3_speed.bin
# ... `load` to flash, set your breakpoints with `break`, ...
```

The board also includes a serial interface that you can tap in with your favourite serial monitor.

```shell
# With miniterm...
miniterm.py /dev/ttyACM0
# ... or screen
screen /dev/ttyACM0 9600
```

### STM32L100 Discovery

`TODO: Write this when you get the board.`

## Build System

The build system of PQM3 is quite modular and supports multiple targets.
The main configuration is happening in the `common/config.mk` file.
This file will set the general compilation/linker flags that are
independent to the target platform.
It will then also include a platform dependent file, named after the
value of the `PLATFORM` variable (e.g., the `common/sam3x8e.mk` for the
Arduino DUE).
This platform dependent file will then set all the platform specific
compilation flags and define a `libpqm3hal.a` target that contains the
code for the platform abstraction layer.
Furthermore, this makefile should set the `EXCLUDED_SCHEMES` variable
that contains a list of patterns defining the Schemes that will not fit
this target platform.

The configuration can be parameterized by the following variables:

- `PLATFORM=<yourplatform>`: The chosen target board/platform.
- `DEBUG=1`: Compile all code without optimization and with debug symbols.
- `OPT_SIZE=1`: Optimize all code for size (otherwise the default is `-O3`).
- `LTO=1`: Enable link-time optimization.
- `AIO=1`: Use all-in-one compilation of schemes, i.e. pass all sources
  instead of compiled modules to the linking step (this can, in some
  cases, be faster than link-time optimization).

The `common/config.mk` also includes a mechanism that remembers all the
values of the the chosen configuration variables named above.
It will generate and include a `obj/.config.mk` file, that contains the
chosen configuration.
If you run `make` a second time with changed values, the compilation
will fail and you will have to run `make clean`.
This is to prevent accidental mixing of compiled code for different
platforms or different optimization levels.

The build system now also discovers and compiles all schemes it finds in
the configured search paths.
This mechanism is present in the `common/schemes.mk` file.
A small shell script is used to discover all folders containing schemes,
and the result is a `obj/.schemes.mk` file that is included by the make
file.
The make file will then define all library- and test-targets for all
schemes accordingly.

The build system will also build a library of symmetric ciphers and hash
functions that are used by the kem/sign schemes.
This is done in the `common/crypto.mk` file.
All code is compiled twice, once with and without the
`-DPROFILE_HASHING` compiler flag.
The flag should turn on profiling functionality in the library.
The `*_hashing` tests then use this profiled library instead of the
normal one.
