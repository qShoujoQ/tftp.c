# TFTP client addon functions and data structures

Provides very simple TFTP client functionality - sending and receiving array of bytes from TFTP server.

Error handling
-----

```c
typedef struct tftpc_error_client_s {
    enum tftpc_error_client_e code;
    const char* message;
} tftpc_error_client_t;
```
Basic error type, doesn't need to be freed.

```c
enum tftpc_error_client_e {
    TFTPC_ERROR_CLIENT_NONE = 0,
    TFTPC_ERROR_CLIENT_UNKNOWN,
    TFTPC_ERROR_CLIENT_NULL_ARG,
    TFTPC_ERROR_CLIENT_PACKET_MALFORMED,
    TFTPC_ERROR_CLIENT_PARAM_INVALID,
    TFTPC_ERROR_CLIENT_SERVER_NOT_FOUND,
    TFTPC_ERROR_CLIENT_SERVER_ERROR,
    TFTPC_ERROR_CLIENT_TFTP_ERROR,
};
```
Error codes present in all tftpc_error_client_t instances.

Functions
-----

```c
uint8_t* tftpc_client_get (
    int udp_sock_fd,
    const char* server_addr,
    const char* file_name,
    const char* mode,
    size_t* out_file_size,
    tftpc_error_client_t* out_error
);
```
Downloads file from TFTP server. Returns array of bytes, or NULL on error.

Arguments:
| Name | Description |
| ---- | ----------- |
| udp_sock_fd | File descriptor of the UDP socket. User must create, bind and close the socket. Timeouts are also user's responsibility. |
| server_addr | Server IPv4 address in format `ip:port`. |
| file_name | File name to download. In absolute or relative format - depending on server configuration. |
| mode | TFTP mode. Usually `octet`. |
| out_file_size | Pointer to size_t variable. Will be filled with the size of the downloaded file. |
| out_error | Pointer to tftpc_error_client_t variable. Will be filled with error code and message. |

Example:
```c
// initialize network (WSAStartup, etc.)

int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

// set up timeout, bind, etc.

size_t file_size;
tftpc_error_client_t error;
uint8_t* file_data = tftpc_client_get(udp_sock_fd, "127.0.0.1:69", "file.txt", "octet", &file_size, &error);

if (error.code != TFTPC_ERROR_CLIENT_NONE) {
    printf("Error: %s\n", error.message);
} else {
    printf("File size: %zu\n", file_size);
    // do something with file_data
    free(file_data);
}
```

-----

```c
tftpc_error_client_t tftpc_client_put (
    int udp_sock_fd,
    const char* server_addr,
    const char* file_name,
    const char* mode,
    uint8_t* file_data,
    size_t file_size
);
```

Uploads file to TFTP server. Returns error code and message.

Arguments:
| Name | Description |
| ---- | ----------- |
| udp_sock_fd | File descriptor of the UDP socket. User must create, bind and close the socket. Timeouts are also user's responsibility. |
| server_addr | Server IPv4 address in format `ip:port`. |
| file_name | File name to upload. In absolute or relative format - depending on server configuration. Note: It doesn't matter for the client. It will determine, where server will save the file. |
| mode | TFTP mode. Usually `octet`. |
| file_data | Array of bytes to upload. |
| file_size | Size of the array. |

Example:
```c
// initialize network (WSAStartup, etc.)

int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

// set up timeout, bind, etc.

FILE* source_code = fopen("tftp.c", "rb");

// read file and file size
size_t file_size;
uint8_t* file_data;
magic_file_read_function("file.txt", &file_data, &file_size);

tftpc_error_client_t error = tftpc_client_put(udp_sock_fd, "127.0.0.1:69", "file.txt", "octet", file_data, file_size);

if (error.code != TFTPC_ERROR_CLIENT_NONE) {
    printf("Error: %s\n", error.message);
} else {
    printf("File uploaded successfully\n");
}
```
