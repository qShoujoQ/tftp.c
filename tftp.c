#ifndef TFTP_C
#define TFTP_C

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

typedef enum _tftpc_opcode_e
{
    TFTP_INVALID = 0,
    TFTP_RRQ,
    TFTP_WRQ,
    TFTP_DATA,
    TFTP_ACK,
    TFTP_ERROR,
    TFTP_OACK
} tftp_opcode_t;

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
} tftp_error_t; // tftp error codes

typedef enum _tftpc_error_tftpc_e
{
    TFTPC_SUCCESS = 0,
    TFTPC_INVALID_OPCODE,      // got packet with undefined opcode, or passed packet with wrong type to some function.
    TFTPC_INVALID_ARGUMENT,    // passed NULL as argument, or there is something wrong with the arguments
    TFTPC_BUFFER_OFFSET_ERROR, // offset doesn't equal to the size of buffer (packet is corrupted or bug in deserialization code)
    TFTPC_MEMORY_ERROR,        // malloc, realloc, etc. failed. Considered fatal, library will just crash the program.
    TFTPC_OPTION_NOT_FOUND,    // option not found in packet
} tftpc_error_t;               // local tftpc specific error codes

typedef struct _tftpc_option_s
{
    char *option;
    char *value;
} tftp_option_t;

typedef struct _tftpc_packet_s
{
    tftp_opcode_t opcode;

    union
    {
        struct
        {
            char *filename;
            char *mode;
            tftp_option_t *options;
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
            tftp_option_t *options;
            uint16_t ocount; // implementation only, not in standard (not serialized)
        } OACK_T;

    } contents;

} tftp_packet_t;

tftp_packet_t *tftpc_packet_from_buffer(const uint8_t *buffer, uint16_t size, tftpc_error_t *out_error);
uint8_t *tftpc_buffer_from_packet(const tftp_packet_t *packet, uint16_t *out_size, tftpc_error_t *out_error);

tftpc_error_t tftpc_packet_free(tftp_packet_t *packet);

tftp_packet_t *tftpc_packet_new_request(tftp_opcode_t opcode, const char *filename, const char *mode);
tftp_packet_t *tftpc_packet_new_oack();
tftpc_error_t tftpc_packet_add_option(tftp_packet_t *packet, const char *option, const char *value);
char *tftpc_packet_get_option(tftp_packet_t *packet, const char *option, tftpc_error_t *out_error);

tftp_packet_t *tftpc_packet_new_data_ack(uint16_t block, const uint8_t *data, uint16_t data_size); // block, NULL, 0 for ACK
tftp_packet_t *tftpc_packet_new_error(uint16_t code, const char *msg);

tftpc_error_t tftpc_packet_print(const tftp_packet_t *packet);

const char *tftpc_opcode_to_string(tftp_opcode_t opcode);
const char *tftpc_tftp_error_to_string(tftp_error_t error);
const char *tftpc_lib_error_to_string(tftpc_error_t error);

#ifdef TFTPC_IMPLEMENTATION

/* Helper functions & macros */

#define _tftpc_pass_if_not_null(out, err) \
    do                                    \
    {                                     \
        if (out != NULL)                  \
        {                                 \
            *out = err;                   \
        }                                 \
    } while (0)

const char *tftpc_opcode_to_string(tftp_opcode_t opcode)
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

const char *tftpc_tftp_error_to_string(tftp_error_t error)
{
    switch (error)
    {
    case TFTP_ERROR_UNDEFINED:
        return "Undefined error, see error message (if any)";
    case TFTP_ERROR_FILE_NOT_FOUND:
        return "File not found";
    case TFTP_ERROR_ACCESS_VIOLATION:
        return "Access violation";
    case TFTP_ERROR_DISK_FULL:
        return "Disk full or allocation exceeded";
    case TFTP_ERROR_ILLEGAL_OPERATION:
        return "Illegal TFTP operation";
    case TFTP_ERROR_UNKNOWN_TRANSFER_ID:
        return "Unknown transfer ID";
    case TFTP_ERROR_FILE_ALREADY_EXISTS:
        return "File already exists";
    case TFTP_ERROR_NO_SUCH_USER:
        return "No such user";
    default:
        return "Invalid error";
    }
}

const char *tftpc_lib_error_to_string(tftpc_error_t error)
{
    switch (error)
    {
    case TFTPC_SUCCESS:
        return "Success";
    case TFTPC_INVALID_OPCODE:
        return "Invalid opcode - got packet with undefined opcode, or unexpected packet type";
    case TFTPC_INVALID_ARGUMENT:
        return "Invalid argument - received NULL as argument, or argument had unexpected value";
    case TFTPC_BUFFER_OFFSET_ERROR:
        return "Buffer offset error - packet is malformed or bug in deserialization code";
    case TFTPC_MEMORY_ERROR:
        return "Memory error - malloc, realloc, memcpy, etc. failed";
    case TFTPC_OPTION_NOT_FOUND:
        return "Option not found - option not found in packet";
    default:
        return "Invalid error";
    }
}

static void _tftpc_print_buffer(uint8_t *buffer, uint16_t size)
{
    printf("[ ");
    for (int i = 0; i < size - 1; i++)
    {
        printf("0x%02X, ", buffer[i]);
    }
    printf("0x%02X ]\n", buffer[size - 1]);
    return;
}

static void _tftpc_copy_options(uint8_t *buffer, uint16_t *offset, tftp_option_t *options, uint16_t ocount, uint16_t *buf_len)
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

#define _tftpc_copy_string(dest, src, type, field)                                          \
    do                                                                                      \
    {                                                                                       \
        dest->contents.type.field = malloc(strlen((char *)src + i) + 1);                    \
        memcpy(dest->contents.type.field, (uint8_t *)src + i, strlen((char *)src + i) + 1); \
        i += strlen((char *)src + i) + 1;                                                   \
    } while (0)

/* Implementation */

tftpc_error_t tftpc_packet_free(tftp_packet_t *packet)
{
    tftpc_error_t error = TFTPC_SUCCESS;

    switch (packet->opcode)
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
        free(packet->contents.RWRQ_T.filename);
        free(packet->contents.RWRQ_T.mode);

        for (uint16_t i = 0; i < packet->contents.RWRQ_T.ocount; i++)
        {
            free(packet->contents.RWRQ_T.options[i].option);
            free(packet->contents.RWRQ_T.options[i].value);
        }

        free(packet->contents.RWRQ_T.options);
        break;
    case TFTP_DATA:
    case TFTP_ACK:
        if (packet->contents.DATACK_T.data != NULL)
        {
            free(packet->contents.DATACK_T.data);
        }
        break;
    case TFTP_ERROR:
        free(packet->contents.ERROR_T.msg);
        break;
    case TFTP_OACK:
        for (uint16_t i = 0; i < packet->contents.OACK_T.ocount; i++)
        {
            free(packet->contents.OACK_T.options[i].option);
            free(packet->contents.OACK_T.options[i].value);
        }

        free(packet->contents.OACK_T.options);
        break;
    case TFTP_INVALID:
    default:
        error = TFTPC_INVALID_OPCODE;
    }

    free(packet);
    packet = NULL;
    return error;
}

tftp_packet_t *tftpc_packet_from_buffer(const uint8_t *buffer, uint16_t size, tftpc_error_t *out_error)
{
    if (buffer == NULL)
    {
        _tftpc_pass_if_not_null(out_error, TFTPC_INVALID_ARGUMENT);
        return NULL;
    }

    uint16_t i = 0;
    tftp_packet_t *packet = (tftp_packet_t *)malloc(sizeof(tftp_packet_t));

    /* opcode */
    packet->opcode = (buffer[i++] << 8);
    packet->opcode |= buffer[i++];

    switch (packet->opcode)
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
    {
        /* filename */
        _tftpc_copy_string(packet, buffer, RWRQ_T, filename);
        /* mode */
        _tftpc_copy_string(packet, buffer, RWRQ_T, mode);

        //* Maybe put it in a function or macro or something, idk *//
        /* options */
        uint16_t option_c = 0;
        packet->contents.RWRQ_T.options = malloc((option_c + 1) * sizeof(tftp_option_t));

        while (i < size)
        {
            /* reallocaton */
            if (option_c)
                packet->contents.RWRQ_T.options = realloc(packet->contents.RWRQ_T.options, (option_c + 1) * sizeof(tftp_option_t));

            /* option */
            _tftpc_copy_string(packet, buffer, RWRQ_T, options[option_c].option);
            /* value */
            _tftpc_copy_string(packet, buffer, RWRQ_T, options[option_c].value);

            option_c++;
        }

        /* option count */
        packet->contents.RWRQ_T.ocount = option_c;

        if (option_c == 0)
        {
            free(packet->contents.RWRQ_T.options);
            packet->contents.RWRQ_T.options = NULL;
        }
    }
    break;
    case TFTP_DATA:
    case TFTP_ACK:
    {
        /* block number */
        packet->contents.DATACK_T.block = (buffer[i++] << 8);
        packet->contents.DATACK_T.block |= buffer[i++];

        /* data */
        if (packet->opcode == TFTP_DATA)
        {
            packet->contents.DATACK_T.data = malloc(size - i);
            packet->contents.DATACK_T.data_size = size - i;

            memcpy(packet->contents.DATACK_T.data, buffer + i, size - i);
            i += size - i;
        }
        else
        {
            /* ACK - no data */
            packet->contents.DATACK_T.data = NULL;
            packet->contents.DATACK_T.data_size = 0;
        }
    }
    break;
    case TFTP_ERROR:
    {
        /* error code */
        packet->contents.ERROR_T.code = (buffer[i++] << 8);
        packet->contents.ERROR_T.code |= buffer[i++];

        /* error message */
        packet->contents.ERROR_T.msg = malloc(strlen((char *)buffer + i));
        memcpy(packet->contents.ERROR_T.msg, buffer + i, strlen((char *)buffer + i) + 1);

        i += strlen((char *)buffer + i) + 1;
    }
    break;
    case TFTP_OACK:
    {
        //* Maybe put it in a function or macro or something, idk *//
        /* options */
        uint16_t option_c = 0;
        packet->contents.OACK_T.options = malloc((option_c + 1) * sizeof(tftp_option_t));

        while (i < size)
        {
            /* reallocaton */
            if (option_c)
                packet->contents.OACK_T.options = realloc(packet->contents.OACK_T.options, (option_c + 1) * sizeof(tftp_option_t));
            /* option */
            _tftpc_copy_string(packet, buffer, OACK_T, options[option_c].option);
            /* value */
            _tftpc_copy_string(packet, buffer, OACK_T, options[option_c].value);

            option_c++;
        }

        packet->contents.OACK_T.ocount = option_c;
    }
    break;
    case TFTP_INVALID:
    default:
        _tftpc_pass_if_not_null(out_error, TFTPC_INVALID_OPCODE);
        return NULL;
    }

    if (i != size)
    {
        if (buffer[i + 1] == 0x00) // some servers end error packets with two null bytes, idk why
            goto trust_me;

        printf("buffer offset: %d vs size: %d. IM GONNA BLOW UP!!!!\n", i, size); // been getting some problems with this function, idk.
        _tftpc_print_buffer((uint8_t *)buffer, size);
        _tftpc_pass_if_not_null(out_error, TFTPC_BUFFER_OFFSET_ERROR);
        return NULL;
    }

trust_me:

    _tftpc_pass_if_not_null(out_error, TFTPC_SUCCESS);

    return packet;
}

uint8_t *tftpc_buffer_from_packet(const tftp_packet_t *packet, uint16_t *out_size, tftpc_error_t *out_error)
{
    if (packet == NULL)
    {
        _tftpc_pass_if_not_null(out_error, TFTPC_INVALID_ARGUMENT);
        return NULL;
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
        uint16_t filename_len = strlen(packet->contents.RWRQ_T.filename) + 1;
        uint16_t mode_len = strlen(packet->contents.RWRQ_T.mode) + 1;

        /* realocation */
        packet_size += filename_len + mode_len;
        buffer = realloc(buffer, packet_size);

        /* file name */
        memcpy(buffer + i, packet->contents.RWRQ_T.filename, filename_len);
        i += filename_len;

        /* mode */
        memcpy(buffer + i, packet->contents.RWRQ_T.mode, mode_len);
        i += mode_len;

        /* options */
        _tftpc_copy_options(buffer, &i, packet->contents.RWRQ_T.options, packet->contents.RWRQ_T.ocount, &packet_size);
    }
    break;
    case TFTP_DATA:
    case TFTP_ACK:
    {
        /* opcode for later */
        tftp_opcode_t opcode = buffer[i - 1];

        /* realocation */
        packet_size += 2 + packet->contents.DATACK_T.data_size;
        buffer = realloc(buffer, packet_size);

        /* block number */
        buffer[i++] = (packet->contents.DATACK_T.block >> 8) & 0xFF;
        buffer[i++] = packet->contents.DATACK_T.block & 0xFF;

        /* data if opcode if right */
        if (opcode == TFTP_DATA)
        {
            memcpy(buffer + i, packet->contents.DATACK_T.data, packet->contents.DATACK_T.data_size);
            i += packet->contents.DATACK_T.data_size;
        }
    }
    break;
    case TFTP_ERROR:
    {

        /* realocation */
        packet_size += 2 + strlen(packet->contents.ERROR_T.msg) + 1;
        buffer = realloc(buffer, packet_size);

        /* error code */
        buffer[i++] = (packet->contents.ERROR_T.code >> 8) & 0xFF;
        buffer[i++] = packet->contents.ERROR_T.code & 0xFF;

        /* error message */
        memcpy(buffer + i, packet->contents.ERROR_T.msg, strlen(packet->contents.ERROR_T.msg) + 1);
        i += strlen(packet->contents.ERROR_T.msg) + 1;
    }
    break;
    case TFTP_OACK:
        _tftpc_copy_options(buffer, &i, packet->contents.OACK_T.options, packet->contents.OACK_T.ocount, &packet_size);
        break;
    case TFTP_INVALID:
    default:
        _tftpc_pass_if_not_null(out_error, TFTPC_INVALID_OPCODE);
        return NULL;
    }

    /* under / overflow detection */
    // assert(i == packet_size);
    if (i != packet_size)
    {
        if (buffer[i + 1] == 0x00)
            goto trust_me;

        printf("buffer offset: %d vs size: %d. IM GONNA BLOW UP!!!!\n", i, packet_size); // been getting some problems with this function, idk.
        _tftpc_print_buffer((uint8_t *)buffer, packet_size);
        _tftpc_pass_if_not_null(out_error, TFTPC_BUFFER_OFFSET_ERROR);
        return NULL;
    }

trust_me:

    _tftpc_pass_if_not_null(out_error, TFTPC_SUCCESS);
    _tftpc_pass_if_not_null(out_size, packet_size);

    return buffer;
}

tftp_packet_t *tftpc_packet_new_request(tftp_opcode_t opcode, const char *filename, const char *mode)
{
    tftp_packet_t *packet = malloc(sizeof(tftp_packet_t));
    packet->opcode = opcode;

    packet->contents.RWRQ_T.filename = malloc(strlen(filename) + 1);
    memcpy(packet->contents.RWRQ_T.filename, filename, strlen(filename) + 1);

    packet->contents.RWRQ_T.mode = malloc(strlen(mode) + 1);
    memcpy(packet->contents.RWRQ_T.mode, mode, strlen(mode) + 1);

    packet->contents.RWRQ_T.options = NULL;
    packet->contents.RWRQ_T.ocount = 0;

    return packet;
}

tftpc_error_t tftpc_packet_add_option(tftp_packet_t *packet, const char *option, const char *value)
{
    // Must work for RRQ, WRQ and OACK_T
    if (packet->opcode != TFTP_RRQ && packet->opcode != TFTP_WRQ && packet->opcode != TFTP_OACK)
    {
        return TFTPC_INVALID_OPCODE;
    }

    tftp_option_t *options;
    uint16_t *ocount;
    if (packet->opcode == TFTP_RRQ || packet->opcode == TFTP_WRQ)
    {
        options = packet->contents.RWRQ_T.options;
        ocount = &packet->contents.RWRQ_T.ocount;
    }
    else
    {
        options = packet->contents.OACK_T.options;
        ocount = &packet->contents.OACK_T.ocount;
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
        packet->contents.RWRQ_T.options = options;
    }
    else
    {
        packet->contents.OACK_T.options = options;
    }

    return TFTPC_SUCCESS;
}

#define tftpc_option_add_blksize(packet, blksize) \
    tftpc_packet_add_option(packet, "blksize", blksize)
#define tftpc_option_add_tsize(packet, tsize) \
    tftpc_packet_add_option(packet, "tsize", tsize)
#define tftpc_option_add_timeout(packet, timeout) \
    tftpc_packet_add_option(packet, "timeout", timeout)
#define tftpc_option_add_multicast(packet, multicast) \
    tftpc_packet_add_option(packet, "multicast", multicast)

tftp_packet_t *tftpc_packet_new_data_ack(uint16_t block, const uint8_t *data, uint16_t data_size)
{
    tftp_packet_t *packet = malloc(sizeof(tftp_packet_t));
    packet->opcode = (data == NULL) ? TFTP_ACK : TFTP_DATA;

    packet->contents.DATACK_T.block = block;

    if (data != NULL)
    {
        packet->contents.DATACK_T.data = malloc(data_size);
        memcpy(packet->contents.DATACK_T.data, data, data_size);
        packet->contents.DATACK_T.data_size = data_size;
    }
    else
    {
        packet->contents.DATACK_T.data = NULL;
        packet->contents.DATACK_T.data_size = 0;
    }

    return packet;
}

tftp_packet_t *tftpc_packet_new_error(uint16_t code, const char *msg)
{
    tftp_packet_t *packet = malloc(sizeof(tftp_packet_t));
    packet->opcode = TFTP_ERROR;

    packet->contents.ERROR_T.code = code;

    packet->contents.ERROR_T.msg = malloc(strlen(msg) + 1);
    memcpy(packet->contents.ERROR_T.msg, msg, strlen(msg) + 1);

    return packet;
}

tftp_packet_t *tftpc_packet_new_oack()
{
    tftp_packet_t *packet = malloc(sizeof(tftp_packet_t));
    packet->opcode = TFTP_OACK;

    packet->contents.OACK_T.options = NULL;
    packet->contents.OACK_T.ocount = 0;

    return packet;
}

tftpc_error_t tftpc_packet_print(const tftp_packet_t *packet)
{
    printf("TFTP %s packet\n", tftpc_opcode_to_string(packet->opcode));
    switch (packet->opcode)
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
        printf("filename: %s\n", packet->contents.RWRQ_T.filename);
        printf("mode: %s\n", packet->contents.RWRQ_T.mode);
        printf("options:\n");
        for (uint16_t i = 0; i < packet->contents.RWRQ_T.ocount; i++)
        {
            printf("\t%s: %s\n", packet->contents.RWRQ_T.options[i].option, packet->contents.RWRQ_T.options[i].value);
        }
        break;
    case TFTP_DATA:
    case TFTP_ACK:
        printf("block: %d\n", packet->contents.DATACK_T.block);
        if (packet->opcode == TFTP_DATA)
        {
            printf("data: ");
            _tftpc_print_buffer(packet->contents.DATACK_T.data, packet->contents.DATACK_T.data_size);
        }
        break;
    case TFTP_ERROR:
        printf("code: %d\n", packet->contents.ERROR_T.code);
        printf("msg: %s\n", packet->contents.ERROR_T.msg);
        break;
    case TFTP_OACK:
        printf("options:\n");
        for (uint16_t i = 0; i < packet->contents.OACK_T.ocount; i++)
        {
            printf("\t%s: %s\n", packet->contents.OACK_T.options[i].option, packet->contents.OACK_T.options[i].value);
        }
        break;
    case TFTP_INVALID:
    default:
        return TFTPC_INVALID_OPCODE;
    }

    return TFTPC_SUCCESS;
}

char *tftpc_packet_get_option(tftp_packet_t *packet, const char *option, tftpc_error_t *out_error)
{
    if (packet->opcode != TFTP_RRQ && packet->opcode != TFTP_WRQ && packet->opcode != TFTP_OACK)
    {
        _tftpc_pass_if_not_null(out_error, TFTPC_INVALID_OPCODE);
        return NULL;
    }

    tftp_option_t *options;
    uint16_t *ocount;
    if (packet->opcode == TFTP_RRQ || packet->opcode == TFTP_WRQ)
    {
        options = packet->contents.RWRQ_T.options;
        ocount = &packet->contents.RWRQ_T.ocount;
    }
    else
    {
        options = packet->contents.OACK_T.options;
        ocount = &packet->contents.OACK_T.ocount;
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
