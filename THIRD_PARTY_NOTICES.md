# Third-Party Notices

The current processor does not download or invoke `dpt-shell`. Android
VMProtect processing uses the versioned ARM64 profile under
`full-vmprotect/release/v36`; this notice is retained only as historical
license attribution for earlier builds.

- Project: https://github.com/luoyesiqiu/dpt-shell
- Copyright (c) 2022 luoyesiqiu
- License: MIT

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## DCC, Androguard and DAD

The Android Java2C toolchain vendors an allowlisted subset of DCC revision
`17de4fd3202bd0e46735974211a43cda39fca5f3`, including its patched legacy
Androguard/DAD parser and JNI runtime.

- DCC: https://github.com/amimo/dcc
- Androguard: https://github.com/androguard/androguard
- License: Apache License 2.0
- Copyright: DCC, Anthony Desnos, Geoffroy Gueguen and contributors

The complete Apache License 2.0 text and the retained upstream source headers
are stored under `full-vmprotect/third_party/dcc`.
