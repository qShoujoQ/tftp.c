# TFTPC functions and data structures

Error handling
-----

```c
typedef enum _tftpc_error_tftp_e
{
    TFTP_ERROR_UNDEFINED = 0,
    TFTP_ERROR_FILE_NOT_FOUND,
    TFTP_ERROR_ACCESS_VIOLATION,
    TFTP_ERROR_DISK_FULL,
    TFTP_ERROR_ILLEGAL_OPERATION,
    TFTP_ERROR_UNKNOWN_TRANSFER_ID,
    TFTP_ERROR_FILE_ALREADY_EXISTS,
    TFTP_ERROR_NO_SUCH_USER
} tftpc_error_tftp_t;
```
TFTP errors defined in [RFC 1350](https://datatracker.ietf.org/doc/html/rfc1350).
Not used anywhere in the base library. It's here for user convenience.

```c
typedef enum _tftpc_error_tftpc_e
{
    TFTPC_ERROR_NONE = 0,
    TFTPC_ERROR_INVALID_OPCODE,      // got packet with undefined opcode, or passed packet with wrong type to some function.
    TFTPC_ERROR_INVALID_ARGUMENT,    // passed NULL as argument, or there is something wrong with the arguments
    TFTPC_ERROR_BUFFER_OFFSET_ERROR, // offset doesn't equal to the size of buffer (packet is corrupted or bug in deserialization code)
    TFTPC_ERROR_MEMORY_ERROR,        // malloc, realloc, etc. failed. Considered fatal, library will just crash the program.
    TFTPC_ERROR_OPTION_NOT_FOUND,    // option not found in packet
    TFTPC_ERROR_TFTP_ERROR,          // got error packet from server
    TFTPC_ERROR_UNEXPECTED_RESULT    // packet had unexpected contents (lack of options, data, etc.)
} tftpc_error_lib_t;
```
Library error type, returned from most functions in the library.

```c
typedef enum tftpc_error_kind_e
{
    ERROR_KIND_NET, // defined by the OS, WSAError for windows and errno for linux
    ERROR_KIND_LIB, // tftpc_error_lib_t
    ERROR_KIND_TFTP // tftpc_error_tftp_t
} tftpc_error_kind_t;
```
Not sure where was I going with this one. Will be removed in future.

```c
const char *tftpc_error_to_string(tftpc_error_kind_t kind, uint8_t error);
void tftpc_error_print(tftpc_error_kind_t kind, uint8_t error, const char *message);
```
Used to convert error codes to human-readable strings.

TFTP structures and enums
-----
```c
typedef enum _tftpc_opcode_e
{
    TFTP_INVALID = 0,
    TFTP_RRQ,
    TFTP_WRQ,
    TFTP_DATA,
    TFTP_ACK,
    TFTP_ERROR,
    TFTP_OACK
} tftpc_opcode_t;
```
Basic TFTP opcodes, as defined in [RFC 1350](https://datatracker.ietf.org/doc/html/rfc1350).
Every packet has one of these. Used to determine the type of the packet.

```c
typedef struct _tftpc_option_s
{
    char *name;
    char *value;
} tftpc_option_t;
```
TFTP option. Used to store options in RRQ, WRQ and OACK packets.

```c
typedef struct _tftpc_packet_s
{
    tftpc_opcode_t opcode;

    union
    {
        struct
        {
            char *file_name;
            char *mode;
            tftpc_option_t *options;
            uint16_t o_count; // implementation only, not in standard (not serialized)
        } RWRQ_T;

        struct
        {
            uint16_t block;
            uint8_t *data;      // NULL for ACK
            uint16_t data_size; // 0 for ACK, implementation only, not in standard (not serialized)
        } DATACK_T;

        struct
        {
            uint16_t code;
            char *message;
        } ERROR_T;

        struct
        {
            tftpc_option_t *options;
            uint16_t o_count; // implementation only, not in standard (not serialized)
        } OACK_T;
    } contents;

} tftpc_packet_t;
```
TFTP packet. Data is only valid for the opcode of the packet. Used as representation of the packet in the library.

Public utility functions and macros
-----
```c
#define __pass_if_not_null(out_param, value) do { if (out_param) *out_param = value; } while(0)
```
Macro used to pass value to the output parameter if it's not NULL.

```c
void __print_bytes_hex(const uint8_t *bytes, uint16_t bytes_size);
```
Prints bytes in hex format. Used for debugging. Will be private in future.

```c
void tftpc_packet_print(const tftpc_packet_t *packet);
```
Prints packet contents. Used for debugging.

Methods
-----
```c
const char *tftpc_opcode_to_string(tftpc_opcode_t opcode);
```
Converts opcode to human-readable string.

```c
tftpc_error_lib_t tftpc_packet_add_option(tftpc_packet_t *packet, const char *name, const char *value);
```
Adds option to `packet`. `name` and `value` are expected to be standard, null-terminated strings.
returns:
| Error code | Reason |
| --- | --- |
| TFTPC_ERROR_INVALID_OPCODE | Packet is not RRQ, WRQ or OACK |
| TFTPC_ERROR_INVALID_ARGUMENT | `packet`, `name` or `value` is NULL |
| TFTPC_ERROR_NONE | Option added successfully |

```c
const char *tftpc_packet_get_option(tftpc_packet_t *packet, const char *name, tftpc_error_lib_t *out_error);
```
returns:
| value | Reason |
| --- | --- |
| NULL | Option not found |
| non-NULL | Option value |

`out_error` is set to:
| Error code | Reason |
| --- | --- |
| TFTPC_ERROR_INVALID_ARGUMENT | `packet` or `name` is NULL |
| TFTPC_ERROR_OPTION_NOT_FOUND | Option not found |
| TFTPC_ERROR_NONE | Option found |

```c
void tftpc_packet_free(tftpc_packet_t *packet);
```
Frees memory allocated for `tftpc_packet_t`, including all the strings and options.

```c
tftpc_packet_t *tftpc_packet_from_bytes(const uint8_t *bytes, uint16_t bytes_size, tftpc_error_lib_t *out_error);
```
Deserializes `bytes` - packet data as defined in [RFC 1350](https://datatracker.ietf.org/doc/html/rfc1350) to `tftpc_packet_t`.
`out_error` is set to:
| Error code | Reason |
| --- | --- |
| TFTPC_ERROR_INVALID_ARGUMENT | `bytes` is NULL or `bytes_size` is 0 |
| TFTPC_ERROR_UNEXPECTED_RESULT | OACK packet has no options - isn't fatal |
| TFTPC_ERROR_INVALID_OPCODE | Opcode - first 2 bytes of `bytes` - is not recognized |
| TFTPC_ERROR_BUFFER_OFFSET_ERROR | `bytes_size` is not equal to the size of the packet |
| TFTPC_ERROR_NONE | Packet deserialized successfully |

```c
uint8_t *tftpc_bytes_from_packet(const tftpc_packet_t *packet, uint16_t *out_size, tftpc_error_lib_t *out_error);
```
Serializes `packet` to `uint8_t` array. `out_size` is set to the size of the array.
`out_error` is set to:
| Error code | Reason |
| --- | --- |
| TFTPC_ERROR_INVALID_ARGUMENT | `packet` is NULL |
| TFTPC_ERROR_INVALID_OPCODE | Packet has invalid opcode |
| TFTPC_ERROR_BUFFER_OFFSET_ERROR | internal error - shouldn't happen |
| TFTPC_ERROR_NONE | Packet serialized successfully |


Constructors
-----

```c
tftpc_packet_t *tftpc_packet_create_request(tftpc_opcode_t packet_kind, const char *file_name, const char *mode);
```
Creates RRQ or WRQ packet. `file_name` and `mode` are expected to be standard, null-terminated strings.
returns:
| Value | Reason |
| --- | --- |
| NULL | any of the arguments is NULL or `packet_kind` is not RRQ or WRQ |
| non-NULL | Packet created successfully |

```c
tftpc_packet_t *tftpc_packet_create_data_ack(uint16_t block_no, const uint8_t *opt_data, uint16_t opt_data_size);
```
Creates DATA or ACK packet. `opt_data` and `opt_data_size` are expected to be NULL and 0 for ACK, and non-NULL and non-0 for DATA.
There also are support macros:
```c
#define tftpc_packet_create_ack(block_no) tftpc_packet_create_data_ack(block_no, NULL, 0)
#define tftpc_packet_create_data(block_no, data, data_size) tftpc_packet_create_data_ack(block_no, data, data_size)
```
returns:
| Value | Reason |
| --- | --- |
| NULL | `opt_data` is NULL and `opt_data_size` is not 0 |
| non-NULL | Packet created successfully |

```c
tftpc_packet_t *tftpc_packet_create_oack();
```
Creates OACK packet. Can't fail, except for memory allocation error.

```c
tftpc_packet_t *tftpc_packet_create_error(uint16_t error_code, const char *error_message);
```
Creates ERROR packet. `error_message` is expected to be a standard, null-terminated string.
returns:
| Value | Reason |
| --- | --- |
| NULL | `error_message` is NULL |
| non-NULL | Packet created successfully |
