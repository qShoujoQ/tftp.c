#ifndef TFTP_C
#define TFTP_C

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#else // linux
#include <errno.h>
#endif // os

/* --------------- ERRORS --------------- */

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
    TFTPC_ERROR_NONE = 0,
    TFTPC_ERROR_INVALID_OPCODE,      // got packet with undefined opcode, or passed packet with wrong type to some function.
    TFTPC_ERROR_INVALID_ARGUMENT,    // passed NULL as argument, or there is something wrong with the arguments
    TFTPC_ERROR_BUFFER_OFFSET_ERROR, // offset doesn't equal to the size of buffer (packet is corrupted or bug in deserialization code)
    TFTPC_ERROR_MEMORY_ERROR,        // malloc, realloc, etc. failed. Considered fatal, library will just crash the program.
    TFTPC_ERROR_OPTION_NOT_FOUND,    // option not found in packet
} tftpc_error_lib_t;

const char *tftpc_error_lib_to_string(tftpc_error_lib_t error);
const char *tftpc_error_tftp_to_string(tftpc_error_tftp_t error);

/* ---------------- TFTP ---------------- */

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
            char *file_name;
            char *mode;
            tftpc_option_t *options;
            uint16_t o_count; // implementation only, not in standard (not serialized)
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
            char *message;
        } ERROR_T;

        struct
        {
            tftpc_option_t *options;
            uint16_t o_count; // implementation only, not in standard (not serialized)
        } OACK_T;
    } contents;

} tftpc_packet_t;

tftpc_error_lib_t tftpc_packet_add_option(tftpc_packet_t *packet, const char *name, const char *value);
const char *tftpc_packet_get_option(tftpc_packet_t *packet, const char *name, tftpc_error_lib_t *out_error);

void tftpc_packet_free(tftpc_packet_t *packet);

tftpc_packet_t *tftpc_packet_from_bytes(const uint8_t *bytes, uint16_t bytes_size, tftpc_error_lib_t *out_error);
uint8_t *tftpc_bytes_from_packet(const tftpc_packet_t *packet, uint16_t *out_size, tftpc_error_lib_t *out_error);

tftpc_packet_t *tftpc_packet_create_request(tftpc_opcode_t packet_kind, const char *file_name, const char *mode); // NULL if invalid opcode
tftpc_packet_t *tftpc_packet_create_data_ack(uint16_t block_no, const uint8_t *opt_data, uint16_t opt_data_size); // NULL if invalid opcode
tftpc_packet_t *tftpc_packet_create_oack();
tftpc_packet_t *tftpc_packet_create_error(uint16_t error_code, const char *error_message);

void tftpc_packet_print(const tftpc_packet_t *packet);

/* ------------ IMPLEMENTATION ------------- */

#ifdef TFTPC_IMPLEMENTATION

#define __pass_if_not_null(out_param, value) do { if (out_param) *out_param = value; } while(0)
#define __abort_if_null(ptr) do { if (ptr == NULL) { fprintf(stderr, "NULL argument in %s:%d, aborting...", __FILE__, __LINE__); abort(); } } while(0)

void __print_bytes_hex(const uint8_t *bytes, uint16_t bytes_size)
{
    printf("[ ");
    for (int i = 0; i < bytes_size - 1; i++)
    {
        printf("0x%02X, ", bytes[i]);
    }
    printf("0x%02X ]\n", bytes[bytes_size - 1]);
    return;
}

static char *__alloc_copy_string(const uint8_t *src, uint16_t *offset)
{
    uint16_t str_size = (uint16_t)strlen((char *)src + (*offset)) + 1;

    char *dst = malloc(str_size);

    __abort_if_null(dst);

    memcpy(dst, src + (*offset), str_size);

    *offset += str_size;

    return dst;
}

static uint16_t __a_copy_options_from(tftpc_option_t **dst, const uint8_t *src, uint16_t *out_o_count, uint16_t idx, uint16_t bytes_size)
{
    uint16_t o_count = 0;

    if (dst == NULL || src == NULL || out_o_count == NULL)
    {
        fprintf(stderr, "NULL argument in internal function!!! %s in %s:%d", __FUNCTION__, __FILE__, __LINE__);
        return 0;
    }

    *dst = malloc((o_count + 1) * sizeof(tftpc_option_t));

    __abort_if_null(*dst);

    while (idx < bytes_size)
    {
        if (o_count)
            *dst = realloc(*dst, (o_count + 1) * sizeof(tftpc_option_t));

        (*dst)[o_count].name = __alloc_copy_string(src, &idx);
        (*dst)[o_count].value = __alloc_copy_string(src, &idx);

        o_count++;
    }

    *out_o_count = o_count;

    return idx;
}

static void __a_copy_options_to(uint8_t **dst, uint16_t *offset, uint16_t *size, const tftpc_option_t *src, uint16_t o_count)
{
    for (uint16_t i = 0; i < o_count; i++)
    {
        uint16_t name_len = (uint16_t)strlen(src[i].name) + 1;
        uint16_t value_len = (uint16_t)strlen(src[i].value) + 1;

        *size += name_len + value_len;
        *dst = realloc(*dst, *size);

        memcpy(*dst + (*offset), src[i].name, name_len);
        *offset += name_len;
        memcpy(*dst + (*offset), src[i].value, value_len);
        *offset += value_len;
    }
}

const char *tftpc_opcode_to_string(tftpc_opcode_t opcode)
{
    const char* strings[] = {
        "INVALID",
        "RRQ",
        "WRQ",
        "DATA",
        "ACK",
        "ERROR",
        "OACK"
    };

    if (opcode >= TFTP_INVALID && opcode <= TFTP_OACK)
        return strings[opcode];
    else
        return "UNKNOWN";
}

const char* tftpc_error_lib_to_string(tftpc_error_lib_t error)
{
    const char* lib_error_strings[] = {
        "Success",
        "Invalid opcode - got packet with undefined opcode, or unexpected packet type",
        "Invalid argument - received NULL as argument, or argument had unexpected value",
        "Buffer offset error - packet is malformed or bug in deserialization code",
        "Memory error - malloc, realloc, memcpy, etc. failed",
        "Option not found - option not found in packet",
        "TFTP error - got error packet from server",
        "Unexpected result - packet had unexpected contents (lack of options, data, etc.)"
    };

    if (error >= TFTPC_ERROR_NONE && error <= TFTPC_ERROR_OPTION_NOT_FOUND)
        return lib_error_strings[error];
    else
        return "Unknown error";
}

const char* tftpc_error_tftp_to_string(tftpc_error_tftp_t error)
{
    const char* tftp_error_strings[] = {
        "Undefined error, see error message (if any)",
        "File not found",
        "Access violation",
        "Disk full or allocation exceeded",
        "Illegal TFTP operation",
        "Unknown transfer ID",
        "File already exists",
        "No such user"
    };

    if (error >= TFTP_ERROR_UNDEFINED && error <= TFTP_ERROR_NO_SUCH_USER)
        return tftp_error_strings[error];
    else
        return "Unknown error";
}

tftpc_error_lib_t tftpc_packet_add_option(tftpc_packet_t *packet, const char *name, const char *value)
{
    if (packet->opcode != TFTP_RRQ && packet->opcode != TFTP_WRQ && packet->opcode != TFTP_OACK)
        return TFTPC_ERROR_INVALID_OPCODE;
    if (!name || !value || !packet)
        return TFTPC_ERROR_INVALID_ARGUMENT;

    tftpc_option_t *options;
    uint16_t *o_count;

    if (packet->opcode == TFTP_RRQ || packet->opcode == TFTP_WRQ)
    {
        options = packet->contents.RWRQ_T.options;
        o_count = &packet->contents.RWRQ_T.o_count;
    }
    else
    {
        options = packet->contents.OACK_T.options;
        o_count = &packet->contents.OACK_T.o_count;
    }

    *o_count += 1;
    options = realloc(options, (*o_count) * sizeof(tftpc_option_t));

    options[*o_count - 1].name = malloc(strlen(name) + 1);
    __abort_if_null(options[*o_count - 1].name);
    strcpy_s(options[*o_count - 1].name, strlen(name) + 1, name);

    options[*o_count - 1].value = malloc(strlen(value) + 1);
    __abort_if_null(options[*o_count - 1].value);
    strcpy_s(options[*o_count - 1].value, strlen(value) + 1, value);

    if (packet->opcode == TFTP_RRQ || packet->opcode == TFTP_WRQ)
        packet->contents.RWRQ_T.options = options;
    else
        packet->contents.OACK_T.options = options;

    return TFTPC_ERROR_NONE;
}

const char *tftpc_packet_get_option(tftpc_packet_t *packet, const char *name, tftpc_error_lib_t *out_error)
{
    if (packet == NULL || name == NULL)
    {
        __pass_if_not_null(out_error, TFTPC_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    tftpc_option_t *options;
    uint16_t *o_count;

    if (packet->opcode == TFTP_RRQ || packet->opcode == TFTP_WRQ)
    {
        options = packet->contents.RWRQ_T.options;
        o_count = &packet->contents.RWRQ_T.o_count;
    }
    else
    {
        options = packet->contents.OACK_T.options;
        o_count = &packet->contents.OACK_T.o_count;
    }

    for (uint16_t i = 0; i < *o_count; i++)
    {
        if (strcmp(options[i].name, name) == 0)
        {
            __pass_if_not_null(out_error, TFTPC_ERROR_NONE);
            return options[i].value;
        }
    }

    __pass_if_not_null(out_error, TFTPC_ERROR_OPTION_NOT_FOUND);
    return NULL;
}

void tftpc_packet_free(tftpc_packet_t *packet)
{
    if (!packet)
    {
        fprintf(stderr, "NULL argument in user function!!! %s in %s\n", __FUNCTION__, __FILE__);
        return;
    }

    switch (packet->opcode)
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
        free(packet->contents.RWRQ_T.file_name);
        free(packet->contents.RWRQ_T.mode);

        for (uint16_t i = 0; i < packet->contents.RWRQ_T.o_count; i++)
        {
            free(packet->contents.RWRQ_T.options[i].name);
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
        free(packet->contents.ERROR_T.message);
        break;
    case TFTP_OACK:
        for (uint16_t i = 0; i < packet->contents.OACK_T.o_count; i++)
        {
            free(packet->contents.OACK_T.options[i].name);
            free(packet->contents.OACK_T.options[i].value);
        }

        free(packet->contents.OACK_T.options);
        break;
    }

    free(packet);
    packet = NULL;
}

tftpc_packet_t *tftpc_packet_create_request(tftpc_opcode_t packet_kind, const char *file_name, const char *mode)
{
    if (packet_kind != TFTP_WRQ && packet_kind != TFTP_RRQ)
        return NULL;
    if (!file_name || !mode)
        return NULL;

    tftpc_packet_t *p = (tftpc_packet_t *)malloc(sizeof(tftpc_packet_t));
    __abort_if_null(p);

    p->opcode = packet_kind;

    p->contents.RWRQ_T.mode = malloc(strlen(mode) + 1);
    __abort_if_null(p->contents.RWRQ_T.mode);
    strcpy_s(p->contents.RWRQ_T.mode, strlen(mode) + 1, mode);

    p->contents.RWRQ_T.file_name = malloc(strlen(file_name) + 1);
    __abort_if_null(p->contents.RWRQ_T.file_name);
    strcpy_s(p->contents.RWRQ_T.file_name, strlen(file_name) + 1, file_name);

    p->contents.RWRQ_T.o_count = 0;
    p->contents.RWRQ_T.options = NULL;

    return p;
}

tftpc_packet_t *tftpc_packet_create_data_ack(uint16_t block_no, const uint8_t *opt_data, uint16_t opt_data_size)
{
    if (opt_data == NULL && opt_data_size != 0)
        return NULL;

    tftpc_opcode_t opcode = (opt_data == NULL || opt_data_size == 0) ? TFTP_ACK : TFTP_DATA;

    tftpc_packet_t *packet = (tftpc_packet_t *)malloc(sizeof(tftpc_packet_t));
    __abort_if_null(packet);
    packet->opcode = opcode;

    packet->contents.DATACK_T.block = block_no;

    if (opcode == TFTP_DATA)
    {
        packet->contents.DATACK_T.data = malloc(opt_data_size);
        __abort_if_null(packet->contents.DATACK_T.data);
        memcpy(packet->contents.DATACK_T.data, opt_data, opt_data_size);

        packet->contents.DATACK_T.data_size = opt_data_size;
    }
    else
    {
        packet->contents.DATACK_T.data = NULL;
        packet->contents.DATACK_T.data_size = 0;
    }

    return packet;
}

#define tftpc_packet_create_ack(block_no) tftpc_packet_create_data_ack(block_no, NULL, 0)
#define tftpc_packet_create_data(block_no, data, data_size) tftpc_packet_create_data_ack(block_no, data, data_size)

tftpc_packet_t *tftpc_packet_create_oack()
{
    tftpc_packet_t *packet = (tftpc_packet_t *)malloc(sizeof(tftpc_packet_t));
    __abort_if_null(packet);

    packet->opcode = TFTP_OACK;
    packet->contents.OACK_T.options = NULL;
    packet->contents.OACK_T.o_count = 0;

    return packet;
}

tftpc_packet_t *tftpc_packet_create_error(uint16_t error_code, const char *error_message)
{
    if (!error_message)
        return NULL;

    tftpc_packet_t *packet = (tftpc_packet_t *)malloc(sizeof(tftpc_packet_t));
    __abort_if_null(packet);

    packet->opcode = TFTP_ERROR;
    packet->contents.ERROR_T.code = error_code;

    packet->contents.ERROR_T.message = malloc(strlen(error_message + 1));
    __abort_if_null(packet->contents.ERROR_T.message);
    strcpy_s(packet->contents.ERROR_T.message, strlen(error_message) + 1, error_message);

    return packet;
}

void tftpc_packet_print(const tftpc_packet_t *packet)
{
    if (!packet)
    {
        printf("Packet is NULL!\n");
        return;
    }

    printf("TFTP %s packet\n", tftpc_opcode_to_string(packet->opcode));
    switch (packet->opcode)
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
        printf("file-name: %s\n", packet->contents.RWRQ_T.file_name);
        printf("mode: %s\n", packet->contents.RWRQ_T.mode);
        printf("options:\n");
        for (uint16_t i = 0; i < packet->contents.RWRQ_T.o_count; i++)
        {
            printf("\t%s: %s\n", packet->contents.RWRQ_T.options[i].name, packet->contents.RWRQ_T.options[i].value);
        }
        break;
    case TFTP_DATA:
    case TFTP_ACK:
        printf("block: %d\n", packet->contents.DATACK_T.block);
        if (packet->opcode == TFTP_DATA)
        {
            printf("data: ");
            __print_bytes_hex(packet->contents.DATACK_T.data, packet->contents.DATACK_T.data_size);
        }
        break;
    case TFTP_ERROR:
        printf("code: %d\n", packet->contents.ERROR_T.code);
        printf("message: %s\n", packet->contents.ERROR_T.message);
        break;
    case TFTP_OACK:
        printf("options:\n");
        for (uint16_t i = 0; i < packet->contents.OACK_T.o_count; i++)
        {
            printf("\t%s: %s\n", packet->contents.OACK_T.options[i].name, packet->contents.OACK_T.options[i].value);
        }
        break;
    }
}

tftpc_packet_t *tftpc_packet_from_bytes(const uint8_t *bytes, uint16_t bytes_size, tftpc_error_lib_t *out_error)
{
    if (bytes == NULL || bytes_size == 0)
    {
        __pass_if_not_null(out_error, TFTPC_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    tftpc_packet_t *packet = (tftpc_packet_t *)malloc(sizeof(tftpc_packet_t));
    __abort_if_null(packet);
    uint16_t idx = 0;

    // Opcode
    packet->opcode = (bytes[idx++] << 8);
    packet->opcode |= (bytes[idx++]);

    // Rest
    switch (packet->opcode)
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
        // file name
        (packet->contents.RWRQ_T.file_name) = __alloc_copy_string(bytes, &idx);
        // mode
        (packet->contents.RWRQ_T.mode) = __alloc_copy_string(bytes, &idx);
        // options
        idx = __a_copy_options_from(&packet->contents.RWRQ_T.options, bytes, &packet->contents.RWRQ_T.o_count, idx, bytes_size);

        if (packet->contents.RWRQ_T.o_count == 0 || packet->contents.RWRQ_T.options == NULL)
        {
            free(packet->contents.RWRQ_T.options);
            packet->contents.RWRQ_T.options = NULL;
        }

        break;

    case TFTP_DATA:
    case TFTP_ACK:
        packet->contents.DATACK_T.block = (bytes[idx++] << 8);
        packet->contents.DATACK_T.block |= bytes[idx++];

        if (packet->opcode == TFTP_DATA)
        {
            packet->contents.DATACK_T.data = malloc(bytes_size - idx);
            __abort_if_null(packet->contents.DATACK_T.data);
            packet->contents.DATACK_T.data_size = bytes_size - idx;

            memcpy(packet->contents.DATACK_T.data, bytes + idx, bytes_size - idx);
            idx += bytes_size - idx;
        }
        else
        {
            /* ACK - no data */
            packet->contents.DATACK_T.data = NULL;
            packet->contents.DATACK_T.data_size = 0;
        }

        break;

    case TFTP_ERROR:
        packet->contents.ERROR_T.code = (bytes[idx++] << 8);
        packet->contents.ERROR_T.code |= bytes[idx++];

        packet->contents.ERROR_T.message = __alloc_copy_string(bytes, &idx);

        break;

    case TFTP_OACK:
        idx = __a_copy_options_from(&packet->contents.OACK_T.options, bytes, &packet->contents.OACK_T.o_count, idx, bytes_size);

        if (packet->contents.OACK_T.o_count == 0)
        {
            free(packet->contents.OACK_T.options);
            packet->contents.OACK_T.options = NULL;

            __pass_if_not_null(out_error, TFTPC_ERROR_BUFFER_OFFSET_ERROR);
            free(packet);

            return NULL;
        }

        break;

    default:
        __pass_if_not_null(out_error, TFTPC_ERROR_INVALID_OPCODE);
        return NULL;
    }

    if (idx != bytes_size)
    {
        if (bytes_size - idx == 1 && bytes[idx++] == 0)
            goto null_byte_appended;

        __pass_if_not_null(out_error, TFTPC_ERROR_BUFFER_OFFSET_ERROR);
        printf("expected %d, got %d\n", bytes_size, idx);
        return NULL;
    }

null_byte_appended:
    __pass_if_not_null(out_error, TFTPC_ERROR_NONE);
    return packet;
}

uint8_t *tftpc_bytes_from_packet(const tftpc_packet_t *packet, uint16_t *out_size, tftpc_error_lib_t *out_error)
{
    if (!packet)
    {
        __pass_if_not_null(out_error, TFTPC_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    uint16_t size = 2;
    uint16_t idx = 0;
    uint8_t *bytes = malloc(size);
    __abort_if_null(bytes);

    bytes[idx++] = (packet->opcode >> 8) & 0xFF;
    bytes[idx++] = packet->opcode & 0xFF;

    switch (packet->opcode)
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
    {
        uint16_t file_name_len = (uint16_t)strlen(packet->contents.RWRQ_T.file_name) + 1;
        uint16_t mode_len = (uint16_t)strlen(packet->contents.RWRQ_T.mode) + 1;

        size += file_name_len + mode_len;
        bytes = realloc(bytes, size);

        memcpy(bytes + idx, packet->contents.RWRQ_T.file_name, file_name_len);
        idx += file_name_len;

        memcpy(bytes + idx, packet->contents.RWRQ_T.mode, mode_len);
        idx += mode_len;

        __a_copy_options_to(&bytes, &idx, &size, packet->contents.RWRQ_T.options, packet->contents.RWRQ_T.o_count);
    }
    break;
    case TFTP_DATA:
    case TFTP_ACK:
        size += 2 + packet->contents.DATACK_T.data_size;
        bytes = realloc(bytes, size);

        bytes[idx++] = (packet->contents.DATACK_T.block >> 8) & 0xFF;
        bytes[idx++] = packet->contents.DATACK_T.block & 0xFF;

        if (packet->opcode == TFTP_DATA)
        {
            memcpy(bytes + idx, packet->contents.DATACK_T.data, packet->contents.DATACK_T.data_size);
            idx += packet->contents.DATACK_T.data_size;
        }
        break;

    case TFTP_ERROR:
        size += 2 + (uint16_t)strlen(packet->contents.ERROR_T.message) + 1;
        bytes = realloc(bytes, size);

        bytes[idx++] = (packet->contents.ERROR_T.code >> 8) & 0xFF;
        bytes[idx++] = packet->contents.ERROR_T.code & 0xFF;

        memcpy(bytes + idx, packet->contents.ERROR_T.message, strlen(packet->contents.ERROR_T.message) + 1);
        idx += (uint16_t)strlen(packet->contents.ERROR_T.message) + 1;
        break;

    case TFTP_OACK:
        __a_copy_options_to(&bytes, &idx, &size, packet->contents.OACK_T.options, packet->contents.OACK_T.o_count);
        break;

    default:
        __pass_if_not_null(out_error, TFTPC_ERROR_INVALID_OPCODE);
        return NULL;
    }

    if (idx != size)
    {
        __pass_if_not_null(out_error, TFTPC_ERROR_BUFFER_OFFSET_ERROR);
        return NULL;
    }

    __pass_if_not_null(out_error, TFTPC_ERROR_NONE);
    __pass_if_not_null(out_size, size);

    return bytes;
}

#endif // implementation

#endif // TFTP_C
