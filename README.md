# nvblock

## Block based storage on non volatile memory with wear levelling

nvblock is a small translation layer that provides block based access for
non volatile memories (e.g. eeprom, nor-flash, nand-flash, ...). It is
designed for usage on resource constrained systems. nvblock divides the
non volatile memories in size-configurable blocks and provides standard
read and write routines. It has the following features:

* Configurable block size: with a minimum of 32 bytes (or the write block size
  if this is bigger).

* Wear levelling: the erase of any two (non bad) blocks differ with atmost 1.

* Trim: blocks can be deleted when they are no longer to improve system
  performance

* Data integrity, write (and trim) of sectors are atomic, if during a write the
  power fails the system recovers to the last finished write (or trim).

* Support for bad blocks (optional for eeprom/nor flash, required for nand flash)

The nvblock author is gratefull to the developers of the 
[dhara](https://github.com/dlbeer/dhara) nand flash wear levelling library.
Idea's from the dhara library (e.g. the radix tree) have been adapted in the 
nvblock library.

The minimum block size of 32 byte also imposes a limitation that is built into
nvblock: the maximum number of blocks supported is limited to 2^16-1.

The implementation has almost no assumptions on the non volatile memory (hence
the capability to support different kind of memory). The library can take
advantage of hardware features if available, e.g.:

  * Use internally buffered copy operation.

  * The library consumes no OOB bytes if available.

The implementation requires the hardware routines to be provided. These
routines are documented in `lib/nvblock.h` as a `nvb_config` structure. More
specifically the hardware routines should provide:

  * read, prog, move, comp (optional) routines. When working on non volatile
    memory that uses block erase, the prog and move routines should erase a 
    block when a write is performed to the start of a eraseable block.

  * is_bad/mark_bad routines for non volatile memory that needs bad block
    marking. Blocks marked bad will not be erased nor will they ever be used
    again for writing.

  * is_free routine to determine wether a block is free.

For zephyr users the library provides support for nor-flash devices as a zephyr
module. This module can be enabled by adding it to `example.yaml` in the
`submanifest` folder as:
```
manifest:
  projects:
    - name: nvblock
      url: https://github.com/Laczen/nvblock
      revision: main
```
After `west update` the module should be available and can be found as `nvblock`
in the local workspace. 
