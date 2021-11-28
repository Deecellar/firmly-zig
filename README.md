# firmly-zig
This is a library that manually wraps libfirm, a library for codegen made in C, the library have two sections:
- low_level - this is a 1 to 1  representation on the "firm.h" made in zig manually, difference with a translate C is that we have descriptive enums for node enums and manually written enums that are not well translated in the translate-C version, there is also on top of that helpers to call the code in a more zig way
- codegen - A utility for common things to do and helpers for boilerplate

This lib does not build or link libfirm (yet) since I want to port all the scripts to zig =)


TODO:

CODEGEN - All
Wrapper - Make sure variadic functions are called correctly
