## tftpc - TFTP implementation in C
Based on [rfc1350](http:/datatracker.ietf.org/doc/html/rfc1350) and [rfc2347](http:/datatracker.ietf.org/doc/html/rfc2347)

### Building / using in code
Nothing to build! Just:
```c
#define TFTP_IMPLEMENTATION // for implementation
#include "tftp.c"
```
Why .c? It's in the library name!

Header is standalone and "platform independent", unless you don't have `stdint.h` or `stdlib.h` - then You're on Your own.

Compiles without warnings with `-Wall -Wextra -Werror -pedantic` flags.

It still needs some testing, but is more-or-less complete.

### Usage
Header provides definitions for enum `tftp_opcode_t`, enum `_tftpc_error_e`, simple definition for struct `tftp_option_t` and whole `tftp_packet_t` struct - It's up to You what you do with them. In addition it defines function declarations for functions:

```c
void tftpc_packet_free(tftp_packet_t *packet);
```
For quick and easy freeing of packet memory.
```c
tftp_packet_t *tftpc_packet_from_buffer(const uint8_t *buffer, uint16_t size);
uint8_t *tftpc_buffer_from_packet(const tftp_packet_t *packet, uint16_t *out_size);
```
For serialization / deserialization of packets. Result of those functions must be freed - `tftpc_packet_free` for packet, `free` for buffer.
```c
tftp_packet_t *tftpc_packet_new_request(tftp_opcode_t opcode, const char *filename, const char *mode);
tftp_packet_t *tftpc_packet_new_oack();
void tftpc_packet_add_option(tftp_packet_t *packet, const char *option, const char *value);
char *tftpc_packet_get_option(tftp_packet_t *packet, const char *option);

tftp_packet_t *tftpc_packet_new_data_ack(uint16_t block, const uint8_t *data, uint16_t data_size); // block, NULL, 0 for ACK
tftp_packet_t *tftpc_packet_new_error(uint16_t code, const char *msg);
```
As shortcuts for creating packets. After using one of those, it must be freed with `tftpc_packet_free`.
```c
const char *tftpc_opcode_to_string(tftp_opcode_t opcode);
const char *tftpc_error_to_string(tftp_error_t error);
void tftpc_packet_print(const tftp_packet_t *packet);
```
For debugging purposes.

### Examples
In `examples` directory:
- `client.c` - simple TFTP client implementation, with support for downloading and uploading files. Works with tftpd-hpa on ubuntu and Tftpd64 on Windows.

### Imports
```c
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
```

### License
```
MIT License

Copyright (c) 2023 Mikołaj Trafisz

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
```
