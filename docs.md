### TFTPC functions and data structures

#### Error handling
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

typedef enum _tftpc_error_tftpc_e
{
    TFTPC_SUCCESS = 0,
    TFTPC_INVALID_OPCODE,      // got packet with undefined opcode, or passed packet with wrong type to some function.
    TFTPC_INVALID_ARGUMENT,    // passed NULL as argument, or there is something wrong with the arguments
    TFTPC_BUFFER_OFFSET_ERROR, // offset doesn't equal to the size of buffer (packet is corrupted or bug in deserialization code)
    TFTPC_MEMORY_ERROR,        // malloc, realloc, etc. failed. Not used right now.
    TFTPC_OPTION_NOT_FOUND,    // option not found in packet
    TFTPC_TFTP_ERROR,          // got error packet from server
    TFTPC_UNEXPECTED_RESULT    // packet had unexpected contents (lack of options, data, etc.)
} tftpc_error_lib_t;

typedef enum tftpc_error_kind_e {
    ERROR_KIND_NET,            // defined by the OS, WSAError for windows and errno for linux
    ERROR_KIND_LIB,            // tftpc_error_lib_t
    ERROR_KIND_TFTP            // tftpc_error_tftp_t
} tftpc_error_kind_t;

const char *tftpc_error_to_string(tftpc_error_kind_t kind, uint8_t error);
void tftpc_error_print(tftpc_error_kind_t kind, uint8_t error, const char *msg);
```
Every function, that can produce error without apparent cause (ex. tftpc_packet_create_request will return NULL if given packet kind isn't a request one, but it's obvious enough) will either return one of those error types, or have out-argument you can supply to get the error code.

You can pass error into `tftpc_error_to_string` or straight to `tftpc_error_print` to get human-readable error message.

#### Data types
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

const char *tftpc_opcode_to_string(tftpc_opcode_t opcode);

typedef struct _tftpc_option_s
{
    char *name;
    char *value;
} tftpc_option_t;

typedef struct _tftpc_packet_s
{
    tftpc_opcode_t opcode;

    union
    {
        struct
        {
            char *filename;
            char *mode;
            tftpc_option_t *options;
            uint16_t ocount; // implementation only, not in standard (not serialized)
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
            char *msg;
        } ERROR_T;

        struct
        {
            tftpc_option_t *options;
            uint16_t ocount; // implementation only, not in standard (not serialized)
        } OACK_T;
    } contents;

} tftpc_packet_t;
```

#### Functions

```c
tftpc_packet_t *tftpc_packet_create_request(tftpc_opcode_t packet_kind, const char *file_name, const char *mode); // NULL if invalid opcode
tftpc_packet_t *tftpc_packet_create_data_ack(uint16_t block_no, const uint8_t *opt_data, uint16_t opt_data_size); // NULL if invalid opcode
tftpc_packet_t *tftpc_packet_create_oack();
tftpc_packet_t *tftpc_packet_create_error(uint16_t error_code, const char* error_message);                        // NULL if error_message == NULL
```
You can quickly create tftp packet with those functions.

```c
void tftpc_packet_free(tftpc_packet_t *packet);
```
Those packets must be deallocated with this function.

```c
tftpc_error_lib_t tftpc_packet_add_option(tftpc_packet_t *packet, const char *name, const char *value);
const char *tftpc_packet_get_option(tftpc_packet_t *packet, const char *name, tftpc_error_lib_t *out_error);
```
You can add or retrieve option from optionable packet (RRQ, WRQ, OACK) with these functions.

```c
tftpc_packet_t *tftpc_packet_from_bytes(const uint8_t *bytes, uint16_t bytes_size, tftpc_error_lib_t *out_error);
uint8_t *tftpc_bytes_from_packet(const tftpc_packet_t *packet, uint16_t *out_size, tftpc_error_lib_t *out_error);
```
You can serialize and desertialize packets with these functions. Results must be freed with `tftpc_packet_free` for packet and `free` for buffer

```c
void tftpc_packet_print(const tftpc_packet_t *packet);
```
For debugging - You can use this function to quickly print packet contents.
