#ifndef TFTP_CLIENT_H
#define TFTP_CLIENT_H

#include <stdint.h>

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

uint8_t *tftpc_get(int udp_sock, const char* server_addr, const char* filename, const char* mode, uint32_t *out_size, tftpc_client_error_t *out_error);
tftpc_client_error_t tftpc_put(int udp_sock, const char* server_addr, const char* filename, const char* mode, uint8_t *data, uint32_t size);

#endif
