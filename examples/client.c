#define TFTPC_IMPLEMENTATION
#include "../tftp.c"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

// Networking stuff:
#ifndef _WIN32

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define print_net_error(from) perror(from)
#define print_error(from) perror(from)

#else

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define print_error(from) perror(from)

void print_net_error(char *from)
{
    char *s;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&s, 0, NULL);
    printf("WSA error %d: %s (in function %s)\n", WSAGetLastError(), s, from);
    LocalFree(s);
}

#endif

bool tftpc_send_packet(int sock, const struct sockaddr_in *server_addr, const tftp_packet_t *packet)
{
    uint16_t buf_len;
    uint8_t *buffer = tftpc_buffer_from_packet(packet, &buf_len);

    size_t sent = sendto(sock, (const char *)buffer, buf_len, 0, (struct sockaddr *)server_addr, sizeof(*server_addr));

    free(buffer);

    return sent == buf_len;
}

tftp_packet_t *tftpc_receive_packet(int sock, uint16_t blksize, struct sockaddr_in *out_server_addr)
{
    uint8_t *buffer = malloc(blksize + sizeof(tftp_packet_t));
    socklen_t server_addr_len = sizeof(*out_server_addr);

    struct sockaddr_in server_addr;

    int received = recvfrom(sock, (char *)buffer, blksize + sizeof(tftp_packet_t), 0, (struct sockaddr *)&server_addr, &server_addr_len);

    if (received < 0)
    {
        free(buffer);
        return NULL;
    }

    if (out_server_addr != NULL)
    {
        memcpy(out_server_addr, &server_addr, sizeof(server_addr));
    }

    tftp_packet_t *packet = tftpc_packet_from_buffer(buffer, received);
    free(buffer);

    return packet;
}

bool download(const char *file_name, uint32_t tsize, uint16_t blksize, const struct sockaddr_in *server_addr, int socket)
{
    if (tsize == 0 || tsize / blksize >= UINT16_MAX)
    {
        printf("Invalid tsize: %d\n", tsize);
        return false;
    }

    FILE *file = fopen(file_name, "wb");
    if (file == NULL)
    {
        print_error("fopen");
        return false;
    }

    uint16_t block = 0;
    uint32_t bytes_read = 0;
    uint32_t bytes_written = 0;

    tftp_packet_t *zero_ack = tftpc_packet_new_data_ack(block++, NULL, 0);
    if (!tftpc_send_packet(socket, server_addr, zero_ack))
    {
        print_net_error("download -> send zero ack");
        return false;
    }
    tftpc_packet_free(zero_ack);

    // receive data:
    while (bytes_read < tsize)
    {
        tftp_packet_t *data = tftpc_receive_packet(socket, blksize, NULL);
        if (data == NULL)
        {
            fprintf(stderr, "Timeout: tsize = %d, bytes_read = %d\n", tsize, bytes_read);
            print_net_error("download -> receive data");
            return false;
        }

        if (data->opcode == TFTP_ERROR)
        {
            printf("TFTP error %d: %s", data->contents.ERROR_T.code, data->contents.ERROR_T.msg);
            return false;
        }
        if (data->opcode != TFTP_DATA)
        {
            printf("Unexpected opcode: %d\n", data->opcode);
            return false;
        }

        if (data->contents.DATACK_T.block != block)
        {
            printf("Unexpected block: %d\n", data->contents.DATACK_T.block);
            return false;
        }

        bytes_read += data->contents.DATACK_T.data_size;

        if (data->contents.DATACK_T.data_size > 0)
        {
            bytes_written += fwrite(data->contents.DATACK_T.data, 1, data->contents.DATACK_T.data_size, file);
            if (bytes_written != bytes_read)
            {
                fprintf(stderr, "bytes_written = %d, bytes_read = %d\n", bytes_written, bytes_read);
                print_error("fwrite");
                return false;
            }
        }

        tftpc_packet_free(data);
        data = NULL;

        tftp_packet_t *ack = tftpc_packet_new_data_ack(block++, NULL, 0);
        if (!tftpc_send_packet(socket, server_addr, ack))
        {
            print_net_error("download -> send ack");
            return false;
        }
        tftpc_packet_free(ack);
    }

    fclose(file);
    return true;
}

bool upload(const char *file_name, uint16_t blksize, uint32_t tsize, struct sockaddr_in *server_addr, int socket)
{
    if (tsize == 0 || tsize / blksize >= UINT16_MAX)
    {
        printf("Invalid tsize: %d\n", tsize);
        return false;
    }

    FILE *file = fopen(file_name, "rb");
    if (file == NULL)
    {
        print_error("fopen");
        return false;
    }

    uint16_t block = 1;
    uint16_t bytes_read = 0;

    assert(tsize / blksize < UINT16_MAX);

    // upload data
    while (bytes_read < tsize)
    {
        uint8_t *data = (uint8_t *)malloc(blksize);
        size_t read = fread(data, 1, blksize, file);
        if (read == 0)
        {
            print_error("fread");
            return false;
        }

        bytes_read += read;

        tftp_packet_t *data_packet = tftpc_packet_new_data_ack(block++, (const uint8_t *)data, read);
        if (!tftpc_send_packet(socket, server_addr, data_packet))
        {
            print_net_error("upload -> send data");
            return false;
        }
        tftpc_packet_free(data_packet);

        tftp_packet_t *ack = tftpc_receive_packet(socket, blksize, NULL);
        if (ack == NULL)
        {
            print_net_error("upload -> receive ack");
            return false;
        }

        if (ack->opcode == TFTP_ERROR)
        {
            printf("TFTP error %d: %s", ack->contents.ERROR_T.code, ack->contents.ERROR_T.msg);
            return false;
        }
        if (ack->opcode != TFTP_ACK)
        {
            printf("Unexpected opcode: %d\n", ack->opcode);
            return false;
        }

        if (ack->contents.DATACK_T.block != block - 1)
        {
            printf("Unexpected block: %d, expected %d\n", ack->contents.DATACK_T.block, block - 1);
            return false;
        }

        tftpc_packet_free(ack);
        free(data);
    }

    fclose(file);
    return true;
}

size_t get_file_size(FILE *file)
{
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

int main(int argc, char *argv[])
{
    /* Arg parsing */
    if (argc != 4)
    {
        printf("Usage: %s <PUT/GET> <file> <host:port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *mode_str = argv[1];
    if (strcmp(mode_str, "GET") != 0 && strcmp(mode_str, "PUT") != 0)
    {
        printf("Invalid mode: %s\n", mode_str);
        return EXIT_FAILURE;
    }

    const char *file = argv[2];
    char *host = argv[3];
    const char *port = strchr(host, ':');
    if (port == NULL)
        port = ":69";
    else
        host[port - host] = '\0';

    assert(port != NULL);

    /* Network setup */

#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        print_net_error("main");
        return EXIT_FAILURE;
    }
#endif

    tftp_opcode_t request_type = strcmp(mode_str, "GET") == 0 ? TFTP_RRQ : TFTP_WRQ;
    int sock;
    struct sockaddr_in server_addr_inital, server_addr_com, local_addr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        print_net_error("main");
        return EXIT_FAILURE;
    }

    memset(&server_addr_inital, 0, sizeof(server_addr_inital));
    memset(&server_addr_com, 0, sizeof(server_addr_com));
    memset(&local_addr, 0, sizeof(local_addr));

    server_addr_inital.sin_family = AF_INET;
    server_addr_inital.sin_port = htons(atol(port + 1));
    server_addr_inital.sin_addr.s_addr = inet_addr(host);

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(0);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
    {
        print_net_error("main");
        return EXIT_FAILURE;
    }

    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) < 0)
    {
        print_net_error("main");
        return EXIT_FAILURE;
    }

    /* TFTP stuff */
    // request
    uint32_t tsize = 0;
    const uint16_t blksize = 1024;

    if (request_type == TFTP_WRQ)
    {
        FILE *file = fopen(argv[2], "rb");
        if (file == NULL)
        {
            print_error("fopen");
            return EXIT_FAILURE;
        }

        tsize = get_file_size(file);
    }

    tftp_packet_t *request = tftpc_packet_new_request(request_type, file, "octet");

    char *blksize_str = (char *)malloc(16);
    sprintf(blksize_str, "%d", blksize);
    char *tsize_str = (char *)malloc(16);
    sprintf(tsize_str, "%d", tsize);

    tftpc_option_add_blksize(request, blksize_str);
    tftpc_option_add_tsize(request, tsize_str);

    free(blksize_str);
    blksize_str = NULL;
    free(tsize_str);
    tsize_str = NULL;

    if (!tftpc_send_packet(sock, &server_addr_inital, request))
    {
        print_net_error("main");
        return EXIT_FAILURE;
    }

    tftpc_packet_free(request);
    request = NULL;

    // server response
    tftp_packet_t *response = tftpc_receive_packet(sock, blksize, &server_addr_com);
    if (response == NULL)
    {
        print_net_error("main");
        return EXIT_FAILURE;
    }

    if (response->opcode == TFTP_ERROR)
    {
        uint16_t code = response->contents.ERROR_T.code;
        printf("TFTP error %d (%s): %s\n", code, code != 0 ? tftpc_error_to_string(code) : ":", response->contents.ERROR_T.msg);
        tftpc_packet_free(response);
        return EXIT_FAILURE;
    }
    if (response->opcode != TFTP_OACK)
    {
        printf("Unexpected opcode: %d\n", response->opcode);
        tftpc_packet_free(response);
        return EXIT_FAILURE;
    }

    tsize = atoi(tftpc_packet_get_option(response, "tsize"));

    if (atoi(tftpc_packet_get_option(response, "blksize")) != blksize)
    {
        printf("Unexpected blksize: %s\n", tftpc_packet_get_option(response, "blksize"));
        tftpc_packet_free(response);
        return EXIT_FAILURE;
    }

    assert(blksize > 0);
    assert(tsize > 0);

    tftpc_packet_free(response);
    response = NULL;

    switch (request_type)
    {
    case TFTP_RRQ:
        printf("Downloading %s (%d bytes)...\n", file, tsize);
        if (!download(file, tsize, blksize, &server_addr_com, sock))
        {
            return EXIT_FAILURE;
        }
        printf("Done! Dowloaded %s (%d bytes)\n", file, tsize);
        break;
    case TFTP_WRQ:
        printf("Uploading %s (%d bytes)...\n", file, tsize);
        if (!upload(file, blksize, tsize, &server_addr_com, sock))
        {
            return EXIT_FAILURE;
        }
        printf("Done! Uploaded %s (%d bytes)\n", file, tsize);
        break;
    default:
        assert(false);
    }

    // cleanup:
#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    return EXIT_SUCCESS;
}
