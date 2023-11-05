#ifndef TFTP_C
#define TFTP_C

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>

typedef enum
{
    TFTP_INVALID = 0,
    TFTP_RRQ,
    TFTP_WRQ,
    TFTP_DATA,
    TFTP_ACK,
    TFTP_ERROR,
    TFTP_OACK
} tftp_opcode_t;

typedef struct
{
    char *option;
    char *value;
} tftp_option_t;

/*
TFTP Formats

   Type   Op #     Format without header

          2 bytes    string   1 byte     string   1 byte
          -----------------------------------------------
   RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
   WRQ    -----------------------------------------------
          2 bytes    2 bytes       n bytes
          ---------------------------------
   DATA  | 03    |   Block #  |    Data    |
          ---------------------------------
          2 bytes    2 bytes
          -------------------
   ACK   | 04    |   Block #  |
          --------------------
          2 bytes  2 bytes        string    1 byte
          ----------------------------------------
   ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
          ----------------------------------------
*/

typedef struct
{
    tftp_opcode_t opcode;

    union
    {
        struct
        {
            char *filename;
            char *mode;
            tftp_option_t *options;
            uint16_t ocount; // implementation only, not sent nor serialized
        } RWRQ;

        struct
        {
            uint16_t block;
            uint8_t *data;      // NULL for ACK
            uint16_t data_size; // 0 for ACK, implementation only, not sent nor serialized
        } DATACK;

        struct
        {
            uint16_t code;
            char *msg;
        } ERROR;

        struct
        {
            tftp_option_t *options;
            uint16_t ocount; // implementation only, not sent nor serialized
        } OACK;

    } contents;

} tftp_packet_t;

tftp_packet_t *tftpc_packet_from_buffer(uint8_t *buffer, uint16_t size);
uint8_t *tftpc_buffer_from_packet(tftp_packet_t *packet, uint16_t *out_size);

void tftpc_packet_free(tftp_packet_t *packet);

tftp_packet_t *tftpc_packet_new_request(tftp_opcode_t opcode, char *filename, char *mode);
tftp_packet_t *tftpc_packet_new_oack();
void tftpc_packet_add_option(tftp_packet_t *packet, char *option, char *value);
char *tftpc_packet_get_option(tftp_packet_t *packet, char *option);

tftp_packet_t *tftpc_packet_new_data_ack(uint16_t block, uint8_t *data, uint16_t data_size); // block, NULL, 0 for ACK
tftp_packet_t *tftpc_packet_new_error(uint16_t code, char *msg);

void tftpc_packet_print(tftp_packet_t *packet);

#ifdef TFTPC_IMPLEMENTATION

void tftpc_packet_free(tftp_packet_t *packet)
{
    switch (packet->opcode)
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
        free(packet->contents.RWRQ.filename);
        free(packet->contents.RWRQ.mode);

        for (uint16_t i = 0; i < packet->contents.RWRQ.ocount; i++)
        {
            free(packet->contents.RWRQ.options[i].option);
            free(packet->contents.RWRQ.options[i].value);
        }

        free(packet->contents.RWRQ.options);
        break;
    case TFTP_DATA:
    case TFTP_ACK:
        if (packet->contents.DATACK.data != NULL)
        {
            free(packet->contents.DATACK.data);
        }
        break;
    case TFTP_ERROR:
        free(packet->contents.ERROR.msg);
        break;
    case TFTP_OACK:
        for (uint16_t i = 0; i < packet->contents.OACK.ocount; i++)
        {
            free(packet->contents.OACK.options[i].option);
            free(packet->contents.OACK.options[i].value);
        }

        free(packet->contents.OACK.options);
        break;
    case TFTP_INVALID:
    default:
        fprintf(stderr, "invalid opcode: %d\n", packet->opcode);
        exit(1);
    }
}

/* Helper functions*/

char *tftpc_opcode_to_string(tftp_opcode_t opcode)
{
    switch (opcode)
    {
    case TFTP_RRQ:
        return "RRQ";
    case TFTP_WRQ:
        return "WRQ";
    case TFTP_DATA:
        return "DATA";
    case TFTP_ACK:
        return "ACK";
    case TFTP_ERROR:
        return "ERROR";
    case TFTP_OACK:
        return "OACK";
    case TFTP_INVALID:
    default:
        return "INVALID";
    }
}

void print_buff(uint8_t *buffer, uint16_t size)
{
    printf("[ ");
    for (int i = 0; i < size - 1; i++)
    {
        printf("0x%02X, ", buffer[i]);
    }
    printf("0x%02X ]\n", buffer[size - 1]);
    return;
}

void COPY_OPTIONS(uint8_t *buffer, uint16_t *offset, tftp_option_t *options, uint16_t ocount, uint16_t *buf_len)
{
    for (uint16_t i = 0; i < ocount; i++)
    {
        /* lengths */
        uint16_t option_len = strlen(options[i].option) + 1;
        uint16_t value_len = strlen(options[i].value) + 1;

        /* realocation */
        *buf_len += option_len + value_len;
        buffer = realloc(buffer, *buf_len);

        /* copying */
        memcpy(buffer + (*offset), options[i].option, option_len);
        *offset += option_len;
        memcpy(buffer + (*offset), options[i].value, value_len);
        *offset += value_len;
    }
}

#define COPY_STRING(dest, src, field)                                                       \
    do                                                                                      \
    {                                                                                       \
        dest->contents.RWRQ.field = malloc(strlen((char *)src + i) + 1);                    \
        memcpy(dest->contents.RWRQ.field, (uint8_t *)src + i, strlen((char *)src + i) + 1); \
        i += strlen((char *)src + i) + 1;                                                   \
    } while (0)

tftp_packet_t *tftpc_packet_from_buffer(uint8_t *buffer, uint16_t size)
{
    if (buffer == NULL)
    {
        fprintf(stderr, "passed null as argument\n");
        exit(1);
    }

    uint16_t i = 0;
    tftp_packet_t *packet = (tftp_packet_t *)malloc(sizeof(tftp_packet_t));

    /* opcode */
    // packet->opcode = (buffer[i++] << 8) | buffer[i++];
    packet->opcode = (buffer[i++] << 8);
    packet->opcode |= buffer[i++];

    switch (packet->opcode)
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
    {
        /* filename */
        COPY_STRING(packet, buffer, filename);
        /* mode */
        COPY_STRING(packet, buffer, mode);

        //* Maybe put it in a function or macro or something, idk *//
        /* options */
        uint16_t option_c = 0;
        packet->contents.RWRQ.options = malloc((option_c + 1) * sizeof(tftp_option_t));

        while (i < size)
        {
            /* reallocaton */
            if (option_c)
                packet->contents.RWRQ.options = realloc(packet->contents.RWRQ.options, (option_c + 1) * sizeof(tftp_option_t));

            /* option */
            COPY_STRING(packet, buffer, options[option_c].option);
            /* value */
            COPY_STRING(packet, buffer, options[option_c].value);

            option_c++;
        }

        /* option count */
        packet->contents.RWRQ.ocount = option_c;

        if (option_c == 0)
        {
            free(packet->contents.RWRQ.options);
            packet->contents.RWRQ.options = NULL;
        }
    }
    break;
    case TFTP_DATA:
    case TFTP_ACK:
    {
        /* block number */
        // packet->contents.DATACK.block = (buffer[i++] << 8) | buffer[i++];
        packet->contents.DATACK.block = (buffer[i++] << 8);
        packet->contents.DATACK.block |= buffer[i++];

        /* data */
        if (packet->opcode == TFTP_DATA)
        {
            packet->contents.DATACK.data = malloc(size - i);
            packet->contents.DATACK.data_size = size - i;

            memcpy(packet->contents.DATACK.data, buffer + i, size - i);
            i += size - i;
        }
        else
        {
            /* ACK - no data */
            packet->contents.DATACK.data = NULL;
            packet->contents.DATACK.data_size = 0;
        }
    }
    break;
    case TFTP_ERROR:
    {
        /* error code */
        // packet->contents.ERROR.code = (buffer[i++] << 8) | buffer[i++];
        packet->contents.ERROR.code = (buffer[i++] << 8);
        packet->contents.ERROR.code |= buffer[i++];

        /* error message */
        packet->contents.ERROR.msg = malloc(strlen((char *)buffer + i));
        memcpy(packet->contents.ERROR.msg, buffer + i, strlen((char *)buffer + i) + 1);

        i += strlen((char *)buffer + i) + 1;
    }
    break;
    case TFTP_OACK:
    {
        //* Maybe put it in a function or macro or something, idk *//
        /* options */
        uint16_t option_c = 0;
        packet->contents.OACK.options = malloc((option_c + 1) * sizeof(tftp_option_t));

        while (i < size)
        {
            /* reallocaton */
            if (option_c)
                packet->contents.OACK.options = realloc(packet->contents.OACK.options, (option_c + 1) * sizeof(tftp_option_t));
            /* option */
            /* COPY_STRING(packet, buffer, options[option_c].option); */ // crashes for some reason XDD nie mam siły kurwa
            packet->contents.OACK.options[option_c].option = malloc(strlen((char *)buffer + i) + 1);
            memcpy(packet->contents.OACK.options[option_c].option, buffer + i, strlen((char *)buffer + i) + 1);
            i += strlen((char *)buffer + i) + 1;
            /* value */
            /* COPY_STRING(packet, buffer, options[option_c].value); */
            packet->contents.OACK.options[option_c].value = malloc(strlen((char *)buffer + i) + 1);
            memcpy(packet->contents.OACK.options[option_c].value, buffer + i, strlen((char *)buffer + i) + 1);
            i += strlen((char*)buffer + i) + 1;

            option_c++;
        }

        packet->contents.OACK.ocount = option_c;
    }
    break;
    case TFTP_INVALID:
    default:
        fprintf(stderr, "invalid opcode: %d\n", packet->opcode);
        exit(1);
    }

    assert(i == size);

    return packet;
}

uint8_t *tftpc_buffer_from_packet(tftp_packet_t *packet, uint16_t *out_size)
{
    if (packet == NULL)
    {
        fprintf(stderr, "passed null as argument\n");
        exit(1);
    }

    uint16_t packet_size = sizeof(uint16_t);
    uint16_t i = 0;
    uint8_t *buffer = (uint8_t *)malloc(packet_size);

    /* opcode */
    buffer[i++] = (packet->opcode << 8) & 0xFF;
    buffer[i++] = packet->opcode & 0xFF;

    switch (buffer[i - 1])
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
    {
        /* lengths */
        uint16_t filename_len = strlen(packet->contents.RWRQ.filename) + 1;
        uint16_t mode_len = strlen(packet->contents.RWRQ.mode) + 1;

        /* realocation */
        packet_size += filename_len + mode_len;
        buffer = realloc(buffer, packet_size);

        /* file name */
        memcpy(buffer + i, packet->contents.RWRQ.filename, filename_len);
        i += filename_len;

        /* mode */
        memcpy(buffer + i, packet->contents.RWRQ.mode, mode_len);
        i += mode_len;

        /* options */
        COPY_OPTIONS(buffer, &i, packet->contents.RWRQ.options, packet->contents.RWRQ.ocount, &packet_size);
    }
    break;
    case TFTP_DATA:
    case TFTP_ACK:
    {
        /* opcode for later */
        tftp_opcode_t opcode = buffer[i - 1];

        /* realocation */
        packet_size += 2 + packet->contents.DATACK.data_size;
        buffer = realloc(buffer, packet_size);

        /* block number */
        buffer[i++] = (packet->contents.DATACK.block >> 8) & 0xFF;
        buffer[i++] = packet->contents.DATACK.block & 0xFF;

        /* data if opcode if right */
        if (opcode == TFTP_DATA)
        {
            memcpy(buffer + i, packet->contents.DATACK.data, packet->contents.DATACK.data_size);
            i += packet->contents.DATACK.data_size;
        }
    }
    break;
    case TFTP_ERROR:
    {

        /* realocation */
        packet_size += 2 + strlen(packet->contents.ERROR.msg) + 1;
        buffer = realloc(buffer, packet_size);

        /* error code */
        buffer[i++] = (packet->contents.ERROR.code >> 8) & 0xFF;
        buffer[i++] = packet->contents.ERROR.code & 0xFF;

        /* error message */
        memcpy(buffer + i, packet->contents.ERROR.msg, strlen(packet->contents.ERROR.msg) + 1);
        i += strlen(packet->contents.ERROR.msg) + 1;
    }
    break;
    case TFTP_OACK:
        COPY_OPTIONS(buffer, &i, packet->contents.OACK.options, packet->contents.OACK.ocount, &packet_size);
        break;
    case TFTP_INVALID:
    default:
        fprintf(stderr, "Invalid TFTP opcode.\n");
        exit(0);
    }

    /* under / overflow detection */
    assert(i == packet_size);

    *out_size = packet_size;
    return buffer;
}

tftp_packet_t *tftpc_packet_new_request(tftp_opcode_t opcode, char *filename, char *mode)
{
    tftp_packet_t *packet = malloc(sizeof(tftp_packet_t));
    packet->opcode = opcode;

    packet->contents.RWRQ.filename = malloc(strlen(filename) + 1);
    memcpy(packet->contents.RWRQ.filename, filename, strlen(filename) + 1);

    packet->contents.RWRQ.mode = malloc(strlen(mode) + 1);
    memcpy(packet->contents.RWRQ.mode, mode, strlen(mode) + 1);

    packet->contents.RWRQ.options = NULL;
    packet->contents.RWRQ.ocount = 0;

    return packet;
}

void tftpc_packet_add_option(tftp_packet_t *packet, char *option, char *value)
{
    // Must work for RRQ, WRQ and OACK
    if (packet->opcode != TFTP_RRQ && packet->opcode != TFTP_WRQ && packet->opcode != TFTP_OACK)
    {
        fprintf(stderr, "invalid opcode: %d\n", packet->opcode);
        exit(1);
    }

    tftp_option_t *options;
    uint16_t *ocount;
    if (packet->opcode == TFTP_RRQ || packet->opcode == TFTP_WRQ)
    {
        options = packet->contents.RWRQ.options;
        ocount = &packet->contents.RWRQ.ocount;
    }
    else
    {
        options = packet->contents.OACK.options;
        ocount = &packet->contents.OACK.ocount;
    }

    /* reallocaton */
    *ocount += 1;
    options = realloc(options, (*ocount) * sizeof(tftp_option_t));

    /* option */
    options[*ocount - 1].option = malloc(strlen(option) + 1);
    memcpy(options[*ocount - 1].option, option, strlen(option) + 1);

    /* value */
    options[*ocount - 1].value = malloc(strlen(value) + 1);
    memcpy(options[*ocount - 1].value, value, strlen(value) + 1);

    if (packet->opcode == TFTP_RRQ || packet->opcode == TFTP_WRQ)
    {
        packet->contents.RWRQ.options = options;
    }
    else
    {
        packet->contents.OACK.options = options;
    }

    return;
}

tftp_packet_t *tftpc_packet_new_data_ack(uint16_t block, uint8_t *data, uint16_t data_size)
{
    tftp_packet_t *packet = malloc(sizeof(tftp_packet_t));
    packet->opcode = (data == NULL) ? TFTP_ACK : TFTP_DATA;

    packet->contents.DATACK.block = block;

    if (data != NULL)
    {
        packet->contents.DATACK.data = malloc(data_size);
        memcpy(packet->contents.DATACK.data, data, data_size);
        packet->contents.DATACK.data_size = data_size;
    }
    else
    {
        packet->contents.DATACK.data = NULL;
        packet->contents.DATACK.data_size = 0;
    }

    return packet;
}

tftp_packet_t *tftpc_packet_new_error(uint16_t code, char *msg)
{
    tftp_packet_t *packet = malloc(sizeof(tftp_packet_t));
    packet->opcode = TFTP_ERROR;

    packet->contents.ERROR.code = code;

    packet->contents.ERROR.msg = malloc(strlen(msg) + 1);
    memcpy(packet->contents.ERROR.msg, msg, strlen(msg) + 1);

    return packet;
}

tftp_packet_t *tftpc_packet_new_oack()
{
    tftp_packet_t *packet = malloc(sizeof(tftp_packet_t));
    packet->opcode = TFTP_OACK;

    packet->contents.OACK.options = NULL;
    packet->contents.OACK.ocount = 0;

    return packet;
}

void tftpc_packet_print(tftp_packet_t *packet)
{
    printf("TFTP %s packet\n", tftpc_opcode_to_string(packet->opcode));
    switch (packet->opcode)
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
        printf("filename: %s\n", packet->contents.RWRQ.filename);
        printf("mode: %s\n", packet->contents.RWRQ.mode);
        printf("options:\n");
        for (uint16_t i = 0; i < packet->contents.RWRQ.ocount; i++)
        {
            printf("\t%s: %s\n", packet->contents.RWRQ.options[i].option, packet->contents.RWRQ.options[i].value);
        }
        break;
    case TFTP_DATA:
    case TFTP_ACK:
        printf("block: %d\n", packet->contents.DATACK.block);
        if (packet->opcode == TFTP_DATA)
        {
            printf("data: ");
            print_buff(packet->contents.DATACK.data, packet->contents.DATACK.data_size);
        }
        break;
    case TFTP_ERROR:
        printf("code: %d\n", packet->contents.ERROR.code);
        printf("msg: %s\n", packet->contents.ERROR.msg);
        break;
    case TFTP_OACK:
        printf("options:\n");
        for (uint16_t i = 0; i < packet->contents.OACK.ocount; i++)
        {
            printf("\t%s: %s\n", packet->contents.OACK.options[i].option, packet->contents.OACK.options[i].value);
        }
        break;
    case TFTP_INVALID:
    default:
        fprintf(stderr, "invalid opcode: %d\n", packet->opcode);
        exit(1);
    }

    return;
}

char *tftpc_packet_get_option(tftp_packet_t *packet, char *option)
{
    if (packet->opcode != TFTP_RRQ && packet->opcode != TFTP_WRQ && packet->opcode != TFTP_OACK)
    {
        fprintf(stderr, "invalid opcode: %d\n", packet->opcode);
        exit(1);
    }

    tftp_option_t *options;
    uint16_t *ocount;
    if (packet->opcode == TFTP_RRQ || packet->opcode == TFTP_WRQ)
    {
        options = packet->contents.RWRQ.options;
        ocount = &packet->contents.RWRQ.ocount;
    }
    else
    {
        options = packet->contents.OACK.options;
        ocount = &packet->contents.OACK.ocount;
    }

    for (uint16_t i = 0; i < *ocount; i++)
    {
        if (strcmp(options[i].option, option) == 0)
        {
            return options[i].value;
        }
    }

    return NULL;
}

#endif

#endif
