### TFTPC client addon functions and data structures
```c
enum tftpc_client_error_e {
   ERROR_NONE,
   ERROR_UNKNOWN,
   ERROR_NULL_ARGUMENT,
   ERROR_PACKET_MALFORMED,
   ERROR_PARAMETERS_INVALID,
   ERROR_SERVER_NOT_FOUND,
   ERROR_SERVER_ERROR,
   ERROR_TFTP_ERROR,
};

typedef struct tftpc_client_error_s {
   enum tftpc_client_error_e error;   
   char *message;
} tftpc_client_error_t;
```
```c
uint8_t *tftpc_get (
   const char* server_addr,
   const char* filename,
   const char* mode,
   uint32_t *out_size,
   tftpc_client_error_t *out_error
);
```
Tries to download given file from tftp server. Returns NULL if error occured, or pointer to the data if download was successful. `out_size` will be set to the size of the data, and `out_error` will be set to the error if any occured.
```c
tftpc_client_error_t tftpc_put (
   const char* server_addr,
   const char* filename,
   const char* mode,
   uint8_t *data,
   uint32_t size
);
```
Tries to upload given data to tftp server. Returns `ERROR_NONE` if upload was successful, or error if any occured.