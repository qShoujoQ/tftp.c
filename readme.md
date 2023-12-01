### Single header tftp implementation in C
Based on [RFC 1350](https://datatracker.ietf.org/doc/html/rfc1350) with [Option](https://datatracker.ietf.org/doc/html/rfc1782) Extension

This is version two of the library, with cleaner and safer codebase.

#### Instalation / Using in project
For main file - nothing to install, just
```c
#include "tftp.c"
```
For tftp client addon You'll need to get the main file, as well as both `tftpc.c` and `tftpc.h`. Then, just include `tftpc.h` in your project, and add `tftpc.c` as source file, or compile it as static library and link it to the project.

#### [TFTPC client addon functions and data structures](addons/docs.md)

#### [TFTPC functions and data structures](docs.md)


