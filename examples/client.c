#ifdef _WIN32
#error "linux only example for now"
#else

#define TFTPC_IMPLEMENTATION
#include "../tftp.c"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

// Networking stuff:
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

bool tftpc_send_packet(int sock, struct sockaddr_in* server_addr, tftp_packet_t* packet) {
    uint16_t buf_len;
    uint8_t* buffer = tftpc_buffer_from_packet(packet, &buf_len);

    ssize_t sent = sendto(sock, buffer, buf_len, 0, (struct sockaddr*)server_addr, sizeof(*server_addr));

    free(buffer);

    return sent == buf_len;
}

tftp_packet_t* tftpc_receive_packet(int sock, struct sockaddr_in* server_addr) {
    uint8_t buffer[1024];
    socklen_t server_addr_len = sizeof(*server_addr);

    ssize_t received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)server_addr, &server_addr_len);

    if (received < 0) {
        perror("recvfrom");
        return NULL;
    }

    return tftpc_packet_from_buffer(buffer, received);
}

bool download(char* file_name, uint16_t tsize, uint16_t blksize, struct sockaddr_in* server_addr, int socket) {
    FILE* file = fopen(file_name, "wb");
    if (file == NULL) {
        perror("fopen");
        return false;
    }

    uint16_t block = 0;
    uint16_t bytes_read = 0;
    uint16_t bytes_written = 0;

    tftp_packet_t* zero_ack = tftpc_packet_new_data_ack(block++, NULL, 0);
    if (!tftpc_send_packet(socket, server_addr, zero_ack)) {
        perror("sendto");
        return false;
    }
    tftpc_packet_free(zero_ack);

    // receive data:
    while (bytes_read < tsize) {
        tftp_packet_t* data = tftpc_receive_packet(socket, server_addr);
        if (data == NULL) {
            // perror("recvfrom"); // reported already
            return false;
        }

        if (data->opcode == TFTP_ERROR) {
            printf("TFTP error %d: %s", data->contents.ERROR.code, data->contents.ERROR.msg);
            return false;
        }
        if (data->opcode != TFTP_DATA) {
            printf("Unexpected opcode: %d\n", data->opcode);
            return false;
        }

        if (data->contents.DATACK.block != block) {
            printf("Unexpected block: %d\n", data->contents.DATACK.block);
            return false;
        }

        bytes_read += data->contents.DATACK.data_size;

        if (data->contents.DATACK.data_size > 0) {
            bytes_written += fwrite(data->contents.DATACK.data, 1, data->contents.DATACK.data_size, file);
            if (bytes_written != bytes_read) {
                perror("fwrite");
                return false;
            }
        }

        tftpc_packet_free(data);
        data = NULL;

        tftp_packet_t* ack = tftpc_packet_new_data_ack(block++, NULL, 0);
        if (!tftpc_send_packet(socket, server_addr, ack)) {
            perror("sendto");
            return false;
        }
        tftpc_packet_free(ack);
    }

    fclose(file);
    return true;
}

bool upload(char* file_name, uint16_t blksize, uint16_t tsize, struct sockaddr_in* server_addr, int socket) {
    FILE* file = fopen(file_name, "rb");
    if (file == NULL) {
        perror("fopen");
        return false;
    }

    uint16_t block = 1;
    uint16_t bytes_read = 0;
    uint16_t bytes_written = 0;

    assert(tsize/blksize < UINT16_MAX);

    // upload data
    while (bytes_read < tsize) {
        uint8_t data[blksize];
        size_t read = fread(data, 1, blksize, file);
        if (read == 0) {
            perror("fread");
            return false;
        }

        bytes_read += read;

        tftp_packet_t* data_packet = tftpc_packet_new_data_ack(block++, data, read);
        if (!tftpc_send_packet(socket, server_addr, data_packet)) {
            perror("sendto");
            return false;
        }
        tftpc_packet_free(data_packet);

        tftp_packet_t* ack = tftpc_receive_packet(socket, server_addr);
        if (ack == NULL) {
            perror("recvfrom");
            return false;
        }

        if (ack->opcode == TFTP_ERROR) {
            printf("TFTP error %d: %s", ack->contents.ERROR.code, ack->contents.ERROR.msg);
            return false;
        }
        if (ack->opcode != TFTP_ACK) {
            printf("Unexpected opcode: %d\n", ack->opcode);
            return false;
        }

        if (ack->contents.DATACK.block != block-1) {
            printf("Unexpected block: %d, expected %d\n", ack->contents.DATACK.block, block-1);
            return false;
        }

        tftpc_packet_free(ack);
        ack = NULL;
    }

    fclose(file);
    return true;
}

char* itoa(int value) {
    char* result = malloc(16);
    sprintf(result, "%d", value);
    return result;
}

// GET / PUT <file> <host:port>
int main(int argc, char* argv[]) {
    /* Arg parsing */
    if (argc != 4) {
        printf("Usage: %s <PUT/GET> <file> <host:port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char* mode_str = argv[1];
    if (strcmp(mode_str, "GET") != 0 && strcmp(mode_str, "PUT") != 0) {
        printf("Invalid mode: %s\n", mode_str);
        return EXIT_FAILURE;
    }

    const char* file = argv[2];
    char* host = argv[3];
    const char* port = strchr(host, ':');
    if (port == NULL) port = ":69"; else host[port - host] = '\0';

    assert(port != NULL);

    /* Network setup */
    tftp_opcode_t request_type = strcmp(mode_str, "GET") == 0 ? TFTP_RRQ : TFTP_WRQ;
    int sock;
    struct sockaddr_in server_addr_inital, server_addr_com, local_addr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
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

    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind");
        return EXIT_FAILURE;
    }

    // set timeout to 3 seconds
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        return EXIT_FAILURE;
    }

    /* TFTP stuff */
    // request
    uint16_t tsize = 0;
    uint16_t blksize = 8192;

    if (request_type == TFTP_WRQ) {
        FILE* file = fopen(argv[2], "rb");
        if (file == NULL) {
            perror("fopen");
            return EXIT_FAILURE;
        }

        fseek(file, 0, SEEK_END);
        tsize = ftell(file);
        fclose(file);
    }

    tftp_packet_t* request = tftpc_packet_new_request(request_type, file, "octet");
    tftpc_packet_add_option(request, "blksize", itoa(blksize));
    tftpc_packet_add_option(request, "tsize", itoa(tsize));

    if (!tftpc_send_packet(sock, &server_addr_inital, request)) {
        perror("sendto");
        return EXIT_FAILURE;
    }

    tftpc_packet_free(request);
    request = NULL;

    // server response
    tftp_packet_t* response = tftpc_receive_packet(sock, &server_addr_com);
    if (response == NULL) {
        perror("recvfrom");
        return EXIT_FAILURE;
    }

    if (response->opcode == TFTP_ERROR) {
        printf("TFTP error %d: %s\n", response->contents.ERROR.code, response->contents.ERROR.msg);
        tftpc_packet_free(response);
        return EXIT_FAILURE;
    }
    if (response->opcode != TFTP_OACK) {
        printf("Unexpected opcode: %d\n", response->opcode);
        tftpc_packet_free(response);
        return EXIT_FAILURE;
    }

    tsize = atoi(tftpc_packet_get_option(response, "tsize"));
    blksize = atoi(tftpc_packet_get_option(response, "blksize"));

    assert(blksize > 0);
    assert(tsize > 0);

    tftpc_packet_free(response);
    response = NULL;

    switch (request_type) {
        case TFTP_RRQ:
            printf("Downloading %s (%d bytes)...\n", file, tsize);
            if (!download(file, tsize, blksize, &server_addr_com, sock)) {
                return EXIT_FAILURE;
            }
            printf("Done! Dowloaded %s (%d bytes)\n", file, tsize);
            break;
        case TFTP_WRQ:
            printf("Uploading %s (%d bytes)...\n", file, tsize);
            if (!upload(file, blksize, tsize, &server_addr_com, sock)) {
                return EXIT_FAILURE;
            }
            printf("Done! Uploaded %s (%d bytes)\n", file, tsize);
        break;
        default:
            assert(false);
    }

    // cleanup:
    close(sock);
    return EXIT_SUCCESS;
}

#endif
