### Single header tftp implementation in C
Based on [RFC 1350](https://datatracker.ietf.org/doc/html/rfc1350) with [Option](https://datatracker.ietf.org/doc/html/rfc1782) Extension

This is version two of the library, with cleaner and safer codebase.

#### Instalation / Using in project
For main file - nothing to install, just
```c
#include "tftp.c"
```
For tftp client addon, compile the addons target, include the tftpc.h header and link with libtftpclient.a file.

#### [TFTPC client addon functions and data structures](addons/docs.md)

#### [TFTPC functions and data structures](docs.md)


