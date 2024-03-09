#ifndef TFTP_C_CLIENT
#define TFTP_C_CLIENT

// debug:
#define TFTPC_CLIENT_IMPLEMENTATION

#include <stdint.h>

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

typedef struct tftpc_error_client_s {
    enum tftpc_error_client_e code;
    const char* message;
} tftpc_error_client_t;

uint8_t* tftpc_client_get (
    int udp_sock_fd,
    const char* server_addr,
    const char* file_name,
    const char* mode,
    size_t* out_file_size,
    tftpc_error_client_t* out_error
);

tftpc_error_client_t tftpc_client_put (
    int udp_sock_fd,
    const char* server_addr,
    const char* file_name,
    const char* mode,
    uint8_t* file_data,
    size_t file_size
);

#if defined(_WIN32) || defined(_WIN64)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0601         // >= Windows 7
#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#warning "Not tested yet"
#endif

#ifdef TFTPC_CLIENT_IMPLEMENTATION
#define TFTPC_IMPLEMENTATION
#include "../tftp.c"

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#define DBG_PRINT(fmt, ...) printf("[DEBUG]\t" fmt "\n", ##__VA_ARGS__)

static tftpc_error_client_t _new_client_error (enum tftpc_error_client_e code, const char* message) {
    tftpc_error_client_t error;
    error.code = code;
    error.message = message;
    return error;
}

static void tftpc_packet_error_to_string (tftpc_packet_t* error_packet, char* out_str) {
    const char* error_str = tftpc_error_to_string(ERROR_KIND_TFTP, (uint8_t) error_packet->contents.ERROR_T.code);
    snprintf(out_str, 64, "TFTP error %d (%s): %s", error_packet->contents.ERROR_T.code, error_str, error_packet->contents.ERROR_T.message);
}

static struct sockaddr_in sockaddr_from_string(const char *addr_port)
{
    char *addr = malloc(strlen(addr_port) + 1);
    snprintf(addr, strlen(addr_port) + 1, "%s", addr_port);

    char *port = strrchr(addr, ':');
    if (port == NULL)
    {
        // set port to 69
        port = addr + strlen(addr);
        // strcpy(port, ":69");
        snprintf(port, 4, ":69");
    }

    *port = '\0';
    port++;

    struct sockaddr_in out_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(atoi(port)),
    };

    inet_pton(AF_INET, addr, &out_addr.sin_addr);

    free(addr);
    return out_addr;
}

static tftpc_error_client_t _send_packet (int udp_sock_fd, const struct sockaddr_in* server_addr, tftpc_packet_t* packet) {
    if (server_addr == NULL || packet == NULL) {
        return _new_client_error(TFTPC_ERROR_CLIENT_NULL_ARG, "Server address and packet must not be NULL");
    }

    uint16_t buffer_size;
    tftpc_error_lib_t e;

    uint8_t* buffer = tftpc_bytes_from_packet(packet, &buffer_size, &e);

    if (e != TFTPC_ERROR_NONE) {
        free(buffer);

        switch (e) {
            case TFTPC_ERROR_INVALID_ARGUMENT:
                return _new_client_error(TFTPC_ERROR_CLIENT_NULL_ARG, "Packet must not be NULL");
            case TFTPC_ERROR_BUFFER_OFFSET_ERROR:
                return _new_client_error(TFTPC_ERROR_CLIENT_PACKET_MALFORMED, "Buffer offset error");
            case TFTPC_ERROR_INVALID_OPCODE:
                return _new_client_error(TFTPC_ERROR_CLIENT_PARAM_INVALID, "Invalid opcode");
            default:
                return _new_client_error(TFTPC_ERROR_CLIENT_UNKNOWN, "Unknown error");
        }
    }

    
    if (buffer == NULL) {
        return _new_client_error(TFTPC_ERROR_CLIENT_UNKNOWN, "Failed to convert packet to bytes");
    }

    size_t bytes_sent = sendto(udp_sock_fd, buffer, buffer_size, 0, (struct sockaddr*) server_addr, sizeof(struct sockaddr_in));
    free(buffer);

    if (bytes_sent != buffer_size) {
        return _new_client_error(TFTPC_ERROR_CLIENT_SERVER_ERROR, "Failed to send packet");
    }

    return _new_client_error(TFTPC_ERROR_CLIENT_NONE, "OK");
}

static tftpc_error_client_t _recv_packet (int udp_sock_fd, uint16_t block_size, tftpc_packet_t* out_packet, struct sockaddr_in* out_server_addr) {
    if (out_packet == NULL) {
        return _new_client_error(TFTPC_ERROR_CLIENT_NULL_ARG, "Packet must not be NULL");
    }

    uint8_t* buffer = malloc(block_size + sizeof(tftpc_packet_t));
    int out_server_addr_len = sizeof(struct sockaddr_in);

    struct sockaddr_in server_addr;
    
    size_t bytes_recv = recvfrom(udp_sock_fd, buffer, block_size + sizeof(tftpc_packet_t), 0, (struct sockaddr*) &server_addr, &out_server_addr_len);

    #ifdef _WIN32
    if (bytes_recv == SOCKET_ERROR) {
        int error_code = WSAGetLastError();
        if (error_code == WSAETIMEDOUT) {
            free(buffer);
            return _new_client_error(TFTPC_ERROR_CLIENT_SERVER_NOT_FOUND, "Server not found");
        }
        free(buffer);
        return _new_client_error(TFTPC_ERROR_CLIENT_SERVER_ERROR, "No activity from server");
    }
    #else
    if (bytes_recv < 0) {
        free(buffer);
        return _new_client_error(TFTPC_ERROR_CLIENT_SERVER_ERROR, "No activity from server");
    }
    #endif

    tftpc_error_lib_t e;
    tftpc_packet_t* packet = tftpc_packet_from_bytes(buffer, (uint16_t) bytes_recv, &e);
    free(buffer);

    if (e != TFTPC_ERROR_NONE) {
        switch (e) {
            case TFTPC_ERROR_INVALID_ARGUMENT:
                return _new_client_error(TFTPC_ERROR_CLIENT_NULL_ARG, "Packet must not be NULL");
            case TFTPC_ERROR_BUFFER_OFFSET_ERROR:
                return _new_client_error(TFTPC_ERROR_CLIENT_PACKET_MALFORMED, "Buffer offset error");
            case TFTPC_ERROR_INVALID_OPCODE:
                return _new_client_error(TFTPC_ERROR_CLIENT_PARAM_INVALID, "Invalid opcode");
            default:
                return _new_client_error(TFTPC_ERROR_CLIENT_UNKNOWN, "Unknown error");
        }
    }

    *out_packet = *packet;
    __pass_if_not_null(out_server_addr, server_addr);

    return _new_client_error(TFTPC_ERROR_CLIENT_NONE, "OK");
}

uint8_t* tftpc_client_get (
    int udp_sock_fd,
    const char* server_addr,
    const char* file_name,
    const char* mode,
    size_t* out_file_size,
    tftpc_error_client_t* out_error
) {
    if (udp_sock_fd < 0 || server_addr == NULL || file_name == NULL || mode == NULL || out_file_size == NULL || out_error == NULL) {
        __pass_if_not_null(out_error, _new_client_error(TFTPC_ERROR_CLIENT_NULL_ARG, "Invalid arguments"));
    }

    /* setting up addresses */

    struct sockaddr_in server_sockaddr_init = sockaddr_from_string(server_addr);
    struct sockaddr_in server_sockaddr;     // resolved after receiving first packet
    memset(&server_sockaddr, 0, sizeof(struct sockaddr_in));

    /* create request */

    uint16_t block_size = 1468;     // TODO: test different block sizes
    uint32_t tsize = 0;

    char blksize_str[16] = {0};
    snprintf(blksize_str, 16, "%d", block_size);

    tftpc_packet_t* request_packet = tftpc_packet_create_request(TFTP_RRQ, file_name, mode);
    tftpc_packet_add_option(request_packet, "blksize", blksize_str);
    tftpc_packet_add_option(request_packet, "tsize", "0");

    assert(request_packet != NULL);
    assert(request_packet->contents.RWRQ_T.o_count == 2);

    /* send request */

    tftpc_error_client_t e = _send_packet(udp_sock_fd, &server_sockaddr_init, request_packet);
    tftpc_packet_free(request_packet);

    if (e.code != TFTPC_ERROR_CLIENT_NONE) {
        __pass_if_not_null(out_error, e);
        return NULL;
    }

    /* receive first packet */

    tftpc_packet_t response;
    e = _recv_packet(udp_sock_fd, block_size + sizeof(tftpc_packet_t), &response, &server_sockaddr);
    
    if (e.code != TFTPC_ERROR_CLIENT_NONE) {
        __pass_if_not_null(out_error, e);
        return NULL;
    }

    bool option_negotiation_broken = false;
    
    switch (response.opcode) {
        case TFTP_OACK: {
            tftpc_error_lib_t e;
            const char* tsize_str = tftpc_packet_get_option(&response, "tsize", &e);
            if (e != TFTPC_ERROR_NONE) {
                __pass_if_not_null(out_error, _new_client_error(TFTPC_ERROR_CLIENT_PACKET_MALFORMED, "First packet must contain tsize option"));
                return NULL;
            }
            tsize = atoi(tsize_str);
            const char* blksize_str = tftpc_packet_get_option(&response, "blksize", &e);
            if (e != TFTPC_ERROR_NONE) {
                __pass_if_not_null(out_error, _new_client_error(TFTPC_ERROR_CLIENT_PACKET_MALFORMED, "First packet must contain blksize option"));
                return NULL;
            }
            block_size = atoi(blksize_str);
        }
            break;
        case TFTP_DATA:
            option_negotiation_broken = true;
        case TFTP_ERROR: {
            char error_str[64];
            tftpc_packet_error_to_string(&response, error_str);
            __pass_if_not_null(out_error, _new_client_error(TFTPC_ERROR_CLIENT_TFTP_ERROR, error_str));
            return NULL;
        }
        default:
            __pass_if_not_null(out_error, _new_client_error(TFTPC_ERROR_CLIENT_PACKET_MALFORMED, "First packet must be DATA or ERROR"));
            return NULL;
    }

    /* send ACK */

    tftpc_packet_t* zero_ack = tftpc_packet_create_ack(0);
    e = _send_packet(udp_sock_fd, &server_sockaddr, zero_ack);
    tftpc_packet_free(zero_ack);
    if (e.code != TFTPC_ERROR_CLIENT_NONE) {
        __pass_if_not_null(out_error, e);
        return NULL;
    }

    /* receive file */

    uint8_t* file_data;
    if (tsize == 0 && option_negotiation_broken) {
        file_data = calloc(1, block_size);
    } else {
        file_data = calloc(1, tsize);
    }

    if (file_data == NULL) {
        __pass_if_not_null(out_error, _new_client_error(TFTPC_ERROR_CLIENT_UNKNOWN, "Failed to allocate memory"));
        return NULL;
    }

    uint32_t file_data_size = 0;
    uint16_t block_number = 1;

    tftpc_packet_t data_packet;
    tftpc_packet_t* ack_packet = tftpc_packet_create_ack(0);

    do {
        recv_data:
        e = _recv_packet(udp_sock_fd, block_size + sizeof(tftpc_packet_t), &data_packet, &server_sockaddr);
        if (e.code != TFTPC_ERROR_CLIENT_NONE) {
            __pass_if_not_null(out_error, e);
            tftpc_packet_free(ack_packet);
            free(file_data);
            return NULL;
        }

        if (data_packet.opcode == TFTP_ERROR) {
            char error_str[64];
            tftpc_packet_error_to_string(&data_packet, error_str);
            __pass_if_not_null(out_error, _new_client_error(TFTPC_ERROR_CLIENT_TFTP_ERROR, error_str));
            tftpc_packet_free(ack_packet);
            free(file_data);
            return NULL;
        }

        if (data_packet.opcode != TFTP_DATA) {
            __pass_if_not_null(out_error, _new_client_error(TFTPC_ERROR_CLIENT_PACKET_MALFORMED, "Expected DATA packet"));
            tftpc_packet_free(ack_packet);
            free(file_data);
            return NULL;
        }

        if (data_packet.contents.DATACK_T.block != block_number) {
            ack_packet->contents.DATACK_T.block = block_number - 1;
            tftpc_error_client_t e = _send_packet(udp_sock_fd, &server_sockaddr, ack_packet);
            if (e.code != TFTPC_ERROR_CLIENT_NONE) {
                __pass_if_not_null(out_error, e);
                tftpc_packet_free(ack_packet);
                free(file_data);
                return NULL;
            }
            goto recv_data;
        }

        // realloc if tsize unknown
        if (tsize == 0 && option_negotiation_broken) {
            file_data = realloc(file_data, file_data_size + data_packet.contents.DATACK_T.data_size);
            if (file_data == NULL) {
                __pass_if_not_null(out_error, _new_client_error(TFTPC_ERROR_CLIENT_UNKNOWN, "Failed to allocate memory"));
                tftpc_packet_free(ack_packet);
                return NULL;
            }
        }

        memcpy(file_data + file_data_size, data_packet.contents.DATACK_T.data, data_packet.contents.DATACK_T.data_size);
        file_data_size += data_packet.contents.DATACK_T.data_size;

        ack_packet->contents.DATACK_T.block = block_number;
        e = _send_packet(udp_sock_fd, &server_sockaddr, ack_packet);
        if (e.code != TFTPC_ERROR_CLIENT_NONE) {
            __pass_if_not_null(out_error, e);
            tftpc_packet_free(ack_packet);
            free(file_data);
            return NULL;
        }

        block_number++;
    } while (data_packet.contents.DATACK_T.data_size == block_size);

    __pass_if_not_null(out_file_size, tsize);
    __pass_if_not_null(out_error, _new_client_error(TFTPC_ERROR_CLIENT_NONE, "OK"));
    return file_data;
}

tftpc_error_client_t tftpc_client_put (
    int udp_sock_fd,
    const char* server_addr,
    const char* file_name,
    const char* mode,
    uint8_t* file_data,
    size_t file_size
) {
    if (udp_sock_fd < 0 || server_addr == NULL || file_name == NULL || mode == NULL || file_data == NULL) {
        return _new_client_error(TFTPC_ERROR_CLIENT_NULL_ARG, "Invalid arguments");
    }

    /* setting up addresses */

    struct sockaddr_in server_sockaddr_init = sockaddr_from_string(server_addr);
    struct sockaddr_in server_sockaddr;     // resolved after receiving first packet

    memset(&server_sockaddr, 0, sizeof(struct sockaddr_in));

    /* create request */

    uint16_t block_size = 1468;     // TODO: test different block sizes
    size_t tsize = file_size;

    char blksize_str[16] = {0};
    snprintf(blksize_str, 16, "%d", block_size);

    char tsize_str[16] = {0};
    snprintf(tsize_str, 16, "%zu", tsize);

    tftpc_packet_t* request_packet = tftpc_packet_create_request(TFTP_WRQ, file_name, mode);
    tftpc_packet_add_option(request_packet, "blksize", blksize_str);
    tftpc_packet_add_option(request_packet, "tsize", tsize_str);

    assert(request_packet != NULL);
    assert(request_packet->contents.RWRQ_T.o_count == 2);

    /* send request */
    
    tftpc_error_client_t e = _send_packet(udp_sock_fd, &server_sockaddr_init, request_packet);
    tftpc_packet_free(request_packet);
    if (e.code != TFTPC_ERROR_CLIENT_NONE) {
        return e;
    }

    /* receive first packet */

    tftpc_packet_t response;
    e = _recv_packet(udp_sock_fd, block_size + sizeof(tftpc_packet_t), &response, &server_sockaddr);
    if (e.code != TFTPC_ERROR_CLIENT_NONE) {
        return e;
    }

    bool option_negotiation_broken = false;

    switch (response.opcode) {
        case TFTP_OACK: {
            tftpc_error_lib_t e;
            const char* tsize_str = tftpc_packet_get_option(&response, "tsize", &e);
            if (e != TFTPC_ERROR_NONE) {
                return _new_client_error(TFTPC_ERROR_CLIENT_PACKET_MALFORMED, "First packet must contain tsize option");
            }
            tsize = atoi(tsize_str);
            const char* blksize_str = tftpc_packet_get_option(&response, "blksize", &e);
            if (e != TFTPC_ERROR_NONE) {
                return _new_client_error(TFTPC_ERROR_CLIENT_PACKET_MALFORMED, "First packet must contain blksize option");
            }
            block_size = atoi(blksize_str);
        }
            break;
        case TFTP_DATA:
            option_negotiation_broken = true;
        case TFTP_ERROR: {
            char error_str[64];
            tftpc_packet_error_to_string(&response, error_str);
            return _new_client_error(TFTPC_ERROR_CLIENT_TFTP_ERROR, error_str);
        }
        default:
            return _new_client_error(TFTPC_ERROR_CLIENT_PACKET_MALFORMED, "First packet must be DATA or ERROR");
    }

    /* send first data packet */

    uint16_t block_number = 1;
    size_t data_index = 0;
    uint8_t* data_block = calloc(1, block_size);

    if (data_block == NULL) {
        return _new_client_error(TFTPC_ERROR_CLIENT_UNKNOWN, "Failed to allocate memory");
    }

    do {
        uint16_t data_size = (uint16_t) (file_size - data_index > block_size ? block_size : file_size - data_index);
        memcpy(data_block, file_data + data_index, data_size);

        tftpc_packet_t* data_packet = tftpc_packet_create_data(block_number, data_block, data_size);
        e = _send_packet(udp_sock_fd, &server_sockaddr, data_packet);
        tftpc_packet_free(data_packet);
        if (e.code != TFTPC_ERROR_CLIENT_NONE) {
            free(data_block);
            return e;
        }

        tftpc_packet_t ack_packet;
        e = _recv_packet(udp_sock_fd, block_size + sizeof(tftpc_packet_t), &ack_packet, &server_sockaddr);
        if (e.code != TFTPC_ERROR_CLIENT_NONE) {
            free(data_block);
            return e;
        }

        if (ack_packet.opcode != TFTP_ACK) {
            free(data_block);
            return _new_client_error(TFTPC_ERROR_CLIENT_PACKET_MALFORMED, "Expected ACK packet");
        }

        if (ack_packet.contents.DATACK_T.block != block_number) {
            free(data_block);
            return _new_client_error(TFTPC_ERROR_CLIENT_PACKET_MALFORMED, "Invalid block number in ACK packet");
        }

        block_number++;
        data_index += data_size;
    } while (data_index < file_size);

    free(data_block);
    return _new_client_error(TFTPC_ERROR_CLIENT_NONE, "OK");
}

#endif // IMPLEMENTATION
#endif
