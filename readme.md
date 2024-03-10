### Single header tftp implementation in C
Based on [RFC 1350](https://datatracker.ietf.org/doc/html/rfc1350) with [Option](https://datatracker.ietf.org/doc/html/rfc1782) Extension

#### Instalation / Using in project
Nothing to install! Just include the header file in your project and you are ready to go.

If you want to implement your own client or server, or use some of the tftp functionality:
```c
#define TFTPC_IMPLEMENTATION
#include "tftp.c" 
```
see [TFTPC functions and data structures](docs.md)

If you just want to download or upload data from tftp server:
```c
#define TFTPC_CLIENT_IMPLEMENTATION
#include "tftpc_client.c"
```
see [TFTPC client addon functions and data structures](addons/client_docs.md)
