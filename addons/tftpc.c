#define TFTPC_IMPLEMENTATION
#include "../tftp.c"
#include "tftpc.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <limits.h>

#if defined(__APPLE__) && defined(__MACH__)
#error "booo hoooo :(((("
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#else // linux
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#endif // os

#define __pass_if_not_null(out, data) ((out != NULL) ? (*out = data) : (void)0)

static tftpc_client_error_t new_client_error(enum tftpc_client_error_e error, char *message)
{
    char message_buf[64];
    strcpy(message_buf, message);

    tftpc_client_error_t out_error = {
        .error = error,
        .message = message_buf,
    };

    return out_error;
}

// "TFTP error <code>: <message>"
void tftpc_packet_error_to_string(tftpc_packet_t *error, char *out)
{
    const char *error_str = tftpc_error_to_string(ERROR_KIND_TFTP, error->contents.ERROR_T.code);
    sprintf(out, "TFTP error %d (%s): %s", error->contents.ERROR_T.code, error_str, error->contents.ERROR_T.msg);
}

// from ipv4:port to sockaddr_in
static struct sockaddr_in sockaddr_from_str(const char *addr_port)
{
    char *addr = malloc(strlen(addr_port) + 1);
    strcpy(addr, addr_port);

    char *port = strrchr(addr, ':');
    if (port == NULL)
    {
        // set port to 69
        port = addr + strlen(addr);
        strcpy(port, ":69");
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

static tftpc_client_error_t tftpc_send_packet(int sock, const struct sockaddr_in *server_addr, const tftpc_packet_t *packet)
{
    if (server_addr == NULL || packet == NULL)
        return new_client_error(ERROR_NULL_ARGUMENT, "Null argument");

    uint16_t buf_len;
    tftpc_error_lib_t e;

    uint8_t *bytes = tftpc_bytes_from_packet(packet, &buf_len, &e);
    if (e != TFTPC_SUCCESS)
    {
        switch (e)
        {
        case TFTPC_INVALID_ARGUMENT:
            return new_client_error(ERROR_NULL_ARGUMENT, "Null argument");
        case TFTPC_BUFFER_OFFSET_ERROR:
            return new_client_error(ERROR_PACKET_MALFORMED, "Buffer offset error");
        case TFTPC_INVALID_OPCODE:
            return new_client_error(ERROR_PACKET_MALFORMED, "Invalid opcode");
        default:
            return new_client_error(ERROR_UNKNOWN, "Unknown error");
        }
    }

    size_t bytes_sent = sendto(sock, bytes, buf_len, 0, (struct sockaddr *)server_addr, sizeof(struct sockaddr_in));
    free(bytes);

    if (bytes_sent != buf_len)
        return new_client_error(ERROR_SERVER_ERROR, "Error sending packet");

    return new_client_error(ERROR_NONE, "Success");
}

static tftpc_packet_t *tftpc_receive_packet(int sock, uint16_t blk_size, struct sockaddr_in *out_addr, tftpc_client_error_t *out_error)
{
    uint8_t *bytes = malloc(blk_size + sizeof(tftpc_packet_t));
    int out_addr_len = sizeof(struct sockaddr_in);

    struct sockaddr_in addr;
    tftpc_client_error_t out_e = new_client_error(ERROR_NONE, "Success");

    size_t bytes_received = recvfrom(sock, bytes, blk_size + sizeof(tftpc_packet_t), 0, (struct sockaddr *)&addr, &out_addr_len);

    if (bytes_received < 0)
    {
        free(bytes);
        out_e = new_client_error(ERROR_SERVER_ERROR, "Error receiving packet");
        __pass_if_not_null(out_error, out_e);
        return NULL;
    }

    tftpc_error_lib_t e;
    tftpc_packet_t *packet = tftpc_packet_from_bytes(bytes, bytes_received, &e);
    free(bytes);

    if (e != TFTPC_SUCCESS && e != TFTPC_UNEXPECTED_RESULT)
    {
        switch (e)
        {
        case TFTPC_INVALID_ARGUMENT:
            out_e = new_client_error(ERROR_NULL_ARGUMENT, "Null argument");
            break;
        case TFTPC_INVALID_OPCODE:
            out_e = new_client_error(ERROR_PACKET_MALFORMED, "Invalid opcode");
            break;
        case TFTPC_BUFFER_OFFSET_ERROR:
            out_e = new_client_error(ERROR_PACKET_MALFORMED, "Buffer offset error");
            break;
        default:
            out_e = new_client_error(ERROR_UNKNOWN, "Unknown error");
            break;
        }

        __pass_if_not_null(out_error, out_e);

        tftpc_packet_free(packet);

        return NULL;
    }

    __pass_if_not_null(out_addr, addr);
    __pass_if_not_null(out_error, out_e);

    return packet;
}

uint8_t *tftpc_get(int udp_sock, const char *server_addr, const char *filename, const char *mode, uint32_t *out_size, tftpc_client_error_t *out_error)
{
    if (filename == NULL || mode == NULL || server_addr == NULL)
    {
        __pass_if_not_null(out_error, new_client_error(ERROR_NULL_ARGUMENT, "Null argument"));
        return NULL;
    }

    /* set up addresses */

    struct sockaddr_in server_addr_initial = sockaddr_from_str(server_addr);
    struct sockaddr_in server_addr_com;

    memset(&server_addr_com, 0, sizeof(struct sockaddr_in));

    /* create request */

    uint16_t blksize = 8192; // TODO: make this configurable maybe
    uint32_t tsize = 0;

    char blksize_str[16] = {0};
    sprintf(blksize_str, "%d", blksize);

    tftpc_packet_t *request = tftpc_packet_create_request(TFTP_RRQ, filename, mode);
    tftpc_packet_add_option(request, "blksize", blksize_str); // we ignore return value, args are already verified
    tftpc_packet_add_option(request, "tsize", "0");           // ^

    assert(request != NULL);
    assert(request->contents.RWRQ_T.ocount == 2);

    /* send request */

    tftpc_client_error_t e = tftpc_send_packet(udp_sock, &server_addr_initial, request);
    if (e.error != ERROR_NONE)
    {
        __pass_if_not_null(out_error, e);
        return NULL;
    }

    tftpc_packet_free(request);
    request = NULL;

    /* receive, parse and validate response */

    tftpc_packet_t *response = tftpc_receive_packet(udp_sock, blksize, &server_addr_com, &e);
    if (e.error != ERROR_NONE)
    {
        __pass_if_not_null(out_error, new_client_error(ERROR_SERVER_NOT_FOUND, "Server didn't answer"));
        return NULL;
    }

    // https://datatracker.ietf.org/doc/html/rfc2347
    switch (response->opcode)
    {
    case TFTP_OACK:
    {
        tftpc_error_lib_t e;
        const char *tsize_str = tftpc_packet_get_option(response, "tsize", &e);
        if (e == TFTPC_INVALID_ARGUMENT || e == TFTPC_OPTION_NOT_FOUND)
        {
            __pass_if_not_null(out_error, new_client_error(ERROR_PACKET_MALFORMED, "OACK packet malformed"));
            return NULL;
        }
        tsize = atoi(tsize_str);
    }
    case TFTP_DATA: // stupid server, i don't want to deal with this
        break;
    case TFTP_ERROR:
    {
        char error_str[64];
        tftpc_packet_error_to_string(response, error_str);
        __pass_if_not_null(out_error, new_client_error(ERROR_TFTP_ERROR, error_str));
        tftpc_packet_free(response);

        return NULL;
    }
    default:
        __pass_if_not_null(out_error, new_client_error(ERROR_SERVER_ERROR, "Unexpected packet"));
        tftpc_packet_free(response);

        return NULL;
    }

    tftpc_packet_free(response);
    response = NULL;

    uint8_t *out_data = malloc(tsize);
    uint32_t data_idx = 0;
    uint16_t blk_num = 1;

    tftpc_packet_t *zero_ack = tftpc_packet_create_data_ack(0, NULL, 0);
    e = tftpc_send_packet(udp_sock, &server_addr_com, zero_ack);
    if (e.error != ERROR_NONE)
    {
        __pass_if_not_null(out_error, e);
        return NULL;
    }

    tftpc_packet_free(zero_ack);
    zero_ack = NULL;

    while (data_idx < tsize)
    {
        tftpc_packet_t *data = tftpc_receive_packet(udp_sock, blksize, &server_addr_com, &e);
        if (e.error != ERROR_NONE)
        {
            __pass_if_not_null(out_error, e);
            return NULL;
        }

        if (data->opcode != TFTP_DATA)
        {
            printf("tsize = %d, data_idx = %d, opcode:%s\n", tsize, data_idx, tftpc_opcode_to_string(data->opcode));
            tftpc_packet_free(data);
            __pass_if_not_null(out_error, new_client_error(ERROR_SERVER_ERROR, "Unexpected packet"));
            return NULL;
        }

        if (data->contents.DATACK_T.block != blk_num)
        {
            printf("expected block %d, got %d\n", blk_num, data->contents.DATACK_T.block);
            tftpc_packet_free(data);
            __pass_if_not_null(out_error, new_client_error(ERROR_SERVER_ERROR, "Unexpected block number"));
            return NULL;
        }

        memcpy(out_data + data_idx, data->contents.DATACK_T.data, data->contents.DATACK_T.data_size);
        data_idx += data->contents.DATACK_T.data_size;

        tftpc_packet_free(data);
        data = NULL;

        tftpc_packet_t *ack = tftpc_packet_create_data_ack(blk_num, NULL, 0);
        e = tftpc_send_packet(udp_sock, &server_addr_com, ack);
        if (e.error != ERROR_NONE)
        {
            __pass_if_not_null(out_error, e);
            return NULL;
        }

        tftpc_packet_free(ack);
        ack = NULL;

        blk_num++;
    }

    __pass_if_not_null(out_size, tsize);
    __pass_if_not_null(out_error, new_client_error(ERROR_NONE, "Success"));
    return out_data;
}

tftpc_client_error_t tftpc_put(int udp_sock, const char *server_addr, const char *filename, const char *mode, uint8_t *data, uint32_t size)
{
    if (filename == NULL || mode == NULL || server_addr == NULL || data == NULL)
    {
        return new_client_error(ERROR_NULL_ARGUMENT, "Null argument");
    }
    else if (udp_sock == 0)
    {
        return new_client_error(ERROR_PARAMETERS_INVALID, "Invalid socket");
    }
    else if (size > UINT16_MAX || size == 0)
    {
        return new_client_error(ERROR_PARAMETERS_INVALID, "Invalid size");
    }

    /* set up addresses */
    struct sockaddr_in server_addr_initial = sockaddr_from_str(server_addr);
    struct sockaddr_in server_addr_com;

    memset(&server_addr_com, 0, sizeof(struct sockaddr_in));

    /* set up parameters */
    uint16_t blksize = 8192; // TODO: make this configurable maybe
    uint32_t tsize = size;

    /* create request */
    char blksize_str[16] = {0};
    sprintf(blksize_str, "%d", blksize);
    char tsize_str[16] = {0};
    sprintf(tsize_str, "%d", tsize);

    tftpc_packet_t *request = tftpc_packet_create_request(TFTP_WRQ, filename, mode);
    tftpc_packet_add_option(request, "blksize", blksize_str); // we ignore return value, args are already verified
    tftpc_packet_add_option(request, "tsize", tsize_str);     // ^

    assert(request != NULL);
    assert(request->contents.RWRQ_T.ocount == 2);

    /* send request */
    tftpc_client_error_t e = tftpc_send_packet(udp_sock, &server_addr_initial, request);
    if (e.error != ERROR_NONE)
    {
        return e;
    }

    tftpc_packet_free(request);
    request = NULL;

    /* receive, parse and validate response */
    tftpc_packet_t *response = tftpc_receive_packet(udp_sock, blksize, &server_addr_com, &e);
    if (e.error != ERROR_NONE)
    {
        return new_client_error(ERROR_SERVER_NOT_FOUND, "Server didn't answer");
    }

    switch (response->opcode)
    {
    case TFTP_OACK:
    {
        tftpc_error_lib_t e;
        const char *tsize_str = tftpc_packet_get_option(response, "tsize", &e);
        if (e == TFTPC_INVALID_ARGUMENT || e == TFTPC_OPTION_NOT_FOUND)
        {
            return new_client_error(ERROR_PACKET_MALFORMED, "OACK packet malformed");
        }
        tsize = atoi(tsize_str);
    }
    case TFTP_ACK: // stupid server, i don't want to deal with this
        break;
    case TFTP_ERROR:
    {
        char error_str[64];
        tftpc_packet_error_to_string(response, error_str);
        return new_client_error(ERROR_TFTP_ERROR, error_str);
    }
    default:
        return new_client_error(ERROR_SERVER_ERROR, "Unexpected packet");
    }

    tftpc_packet_free(response);
    response = NULL;

    uint32_t data_idx = 0;
    uint16_t blk_num = 1;
    uint8_t *data_buf = malloc(blksize);

    while (data_idx < size)
    {
        uint16_t data_size = blksize;
        if (data_idx + blksize > size)
            data_size = size - data_idx;

        memcpy(data_buf, data + data_idx, data_size);

        tftpc_packet_t *data_packet = tftpc_packet_create_data_ack(blk_num, data_buf, data_size);
        e = tftpc_send_packet(udp_sock, &server_addr_com, data_packet);
        if (e.error != ERROR_NONE)
        {
            return e;
        }

        tftpc_packet_free(data_packet);
        data_packet = NULL;

        tftpc_packet_t *ack = tftpc_receive_packet(udp_sock, blksize, &server_addr_com, &e);
        if (e.error != ERROR_NONE)
        {
            return e;
        }

        if (ack->opcode != TFTP_ACK)
        {
            tftpc_packet_free(ack);
            return new_client_error(ERROR_SERVER_ERROR, "Unexpected packet");
        }

        if (ack->contents.DATACK_T.block != blk_num)
        {
            tftpc_packet_free(ack);
            return new_client_error(ERROR_SERVER_ERROR, "Unexpected block number");
        }

        tftpc_packet_free(ack);
        ack = NULL;

        data_idx += data_size;
        blk_num++;
    }

    free(data_buf);

    return new_client_error(ERROR_NONE, "Success");
}
