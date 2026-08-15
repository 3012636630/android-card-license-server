# DCC integration

This directory is an allowlisted subset of amimo/dcc revision
`17de4fd3202bd0e46735974211a43cda39fca5f3`.

Included modules:

- `dex2c/`: DEX-to-C compiler implementation.
- `androguard/`: the legacy patched parser required by that compiler.
- `runtime/`: JNI runtime sources used by generated C++.
- `patches/androguard-v3.3.5.patch`: upstream parser patch record.

Excluded modules include the upstream whole-APK CLI, apktool distribution,
signing tools and keys, demos, tests and GUI. The vendored sources are kept
unchanged; project-specific adapters and build files live outside this
directory.

The upstream runtime names the second `JNI_OnLoad` parameter but does not use
it. Its isolated Android target therefore compiles with
`-Wno-unused-parameter`; all other `-Wall -Wextra` diagnostics remain errors.
