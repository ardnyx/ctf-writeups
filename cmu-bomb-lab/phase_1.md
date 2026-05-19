# Phase 1

Dump of assembler code for function phase_1:

```nasm
   0x0000000000400ee0 <+0>:     sub    rsp,0x8
   0x0000000000400ee4 <+4>:     mov    esi,0x402400
   0x0000000000400ee9 <+9>:     call   0x401338 <strings_not_equal>
   0x0000000000400eee <+14>:    test   eax,eax
   0x0000000000400ef0 <+16>:    je     0x400ef7 <phase_1+23>
   0x0000000000400ef2 <+18>:    call   0x40143a <explode_bomb>
   0x0000000000400ef7 <+23>:    add    rsp,0x8
   0x0000000000400efb <+27>:    ret
```

This one is pretty easy. According to the **System V x86-64 Calling Convention**:

> Parameters to functions are passed in via the registers rdi, rsi, rdx, rcx, r8, and r9.

So as the value inside 0x402400 is being passed to esi (32-bit form of rsi), it's safe to assume 0x402400 contains the string which will be passed in `strings_not_equal(<0x402400)`

We execute x/s 0x402400 to get the value inside that memory, because obviously, it's a string.
