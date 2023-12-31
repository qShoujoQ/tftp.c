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
    TFTPC_SUCCESS = 0,
    TFTPC_INVALID_OPCODE,      // got packet with undefined opcode, or passed packet with wrong type to some function.
    TFTPC_INVALID_ARGUMENT,    // passed NULL as argument, or there is something wrong with the arguments
    TFTPC_BUFFER_OFFSET_ERROR, // offset doesn't equal to the size of buffer (packet is corrupted or bug in deserialization code)
    TFTPC_MEMORY_ERROR,        // malloc, realloc, etc. failed. Considered fatal, library will just crash the program.
    TFTPC_OPTION_NOT_FOUND,    // option not found in packet
    TFTPC_TFTP_ERROR,          // got error packet from server
    TFTPC_UNEXPECTED_RESULT    // packet had unexpected contents (lack of options, data, etc.)
} tftpc_error_lib_t;

typedef enum tftpc_error_kind_e
{
    ERROR_KIND_NET, // defined by the OS, WSAError for windows and errno for linux
    ERROR_KIND_LIB, // tftpc_error_lib_t
    ERROR_KIND_TFTP // tftpc_error_tftp_t
} tftpc_error_kind_t;

const char *tftpc_error_to_string(tftpc_error_kind_t kind, uint8_t error);
void tftpc_error_print(tftpc_error_kind_t kind, uint8_t error, const char *msg);

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
            char *filename;
            char *mode;
            tftpc_option_t *options;
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
            tftpc_option_t *options;
            uint16_t ocount; // implementation only, not in standard (not serialized)
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

#define __pass_if_not_null(out, data) ((out != NULL) ? (*out = data) : (void)0)

static void __print_bytes_hex(const uint8_t *bytes, uint16_t bytes_size)
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
    uint16_t str_size = strlen((char *)src + (*offset)) + 1;

    char *dst = malloc(str_size);
    memcpy(dst, src + (*offset), str_size);

    *offset += str_size;

    return dst;
}

static uint16_t __a_copy_options_from(tftpc_option_t **dst, const uint8_t *src, uint16_t *out_ocount, uint16_t idx, uint16_t bytes_size)
{
    uint16_t ocount = 0;

    if (dst == NULL || src == NULL || out_ocount == NULL)
    {
        fprintf(stderr, "NULL argument in internal function!!! %s in %s:%d", __FUNCTION__, __FILE__, __LINE__);
        return 0;
    }

    *dst = malloc((ocount + 1) * sizeof(tftpc_option_t));

    while (idx < bytes_size)
    {
        if (ocount)
            *dst = realloc(*dst, (ocount + 1) * sizeof(tftpc_option_t));

        (*dst)[ocount].name = __alloc_copy_string(src, &idx);
        (*dst)[ocount].value = __alloc_copy_string(src, &idx);

        ocount++;
    }

    *out_ocount = ocount;

    return idx;
}

static void __a_copy_options_to(uint8_t **dst, uint16_t *offset, uint16_t *size, const tftpc_option_t *src, uint16_t ocount)
{
    for (uint16_t i = 0; i < ocount; i++)
    {
        uint16_t name_len = strlen(src[i].name) + 1;
        uint16_t value_len = strlen(src[i].value) + 1;

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
    default:
        return "INVALID";
    }
}

const char *tftpc_error_to_string(tftpc_error_kind_t kind, uint8_t error)
{
    if (kind == ERROR_KIND_LIB)
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
        case TFTPC_TFTP_ERROR:
            return "TFTP error - got error packet from server";
        case TFTPC_UNEXPECTED_RESULT:
            return "Unexpected result - packet had unexpected contents (lack of options, data, etc.)";
        default:
            return "Unknown error";
        }
    }
    else if (kind == ERROR_KIND_TFTP)
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
            return "Invalid error code";
        }
    }
    else if (kind == ERROR_KIND_NET)
        return "Networking error";

    return "Invalid error kind";
}

void tftpc_error_print(tftpc_error_kind_t kind, uint8_t error, const char *msg)
{
    if (msg == NULL)
        msg = " ";

    if (kind == ERROR_KIND_LIB)
    {
        fprintf(stderr, "[ERROR] [LIB]  %s \t %s\n", msg, tftpc_error_to_string(ERROR_KIND_LIB, error));
    }
    else if (kind == ERROR_KIND_TFTP)
    {
        fprintf(stderr, "[ERROR] [TFTP] %s \t %s\n", msg, tftpc_error_to_string(ERROR_KIND_TFTP, error));
    }
    else if (kind == ERROR_KIND_NET)
    {
#ifdef _WIN32 // windows

        char *wsa_msg;

        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, WSAGetLastError(), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), (LPSTR)&wsa_msg, 0, NULL);

        fprintf(stderr, "[ERROR] [NETWORK] %s \t code: %d, msg: %s", msg, WSAGetLastError(), wsa_msg);

        LocalFree(wsa_msg);

#else // linux

        fprintf(stderr, "[ERROR] [NETWORK] %s \t code: %d, msg: %s", msg, errno, strerror(errno));

#endif // end os
    }
    else
        fprintf(stderr, "[ERROR] [?] %s\n", msg);
}

tftpc_error_lib_t tftpc_packet_add_option(tftpc_packet_t *packet, const char *name, const char *value)
{
    if (packet->opcode != TFTP_RRQ && packet->opcode != TFTP_WRQ && packet->opcode != TFTP_OACK)
        return TFTPC_INVALID_OPCODE;
    if (!name || !value || !packet)
        return TFTPC_INVALID_ARGUMENT;

    tftpc_option_t *options;
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

    *ocount += 1;
    options = realloc(options, (*ocount) * sizeof(tftpc_option_t));

    options[*ocount - 1].name = malloc(strlen(name) + 1);
    strcpy(options[*ocount - 1].name, name);

    options[*ocount - 1].value = malloc(strlen(value) + 1);
    strcpy(options[*ocount - 1].value, value);

    if (packet->opcode == TFTP_RRQ || packet->opcode == TFTP_WRQ)
        packet->contents.RWRQ_T.options = options;
    else
        packet->contents.OACK_T.options = options;

    return TFTPC_SUCCESS;
}

const char *tftpc_packet_get_option(tftpc_packet_t *packet, const char *name, tftpc_error_lib_t *out_error)
{
    if (!packet)
    {
        __pass_if_not_null(out_error, TFTPC_INVALID_ARGUMENT);
        return NULL;
    }

    tftpc_option_t *options;
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
        if (strcmp(options[i].name, name) == 0)
        {
            __pass_if_not_null(out_error, TFTPC_SUCCESS);
            return options[i].value;
        }
    }

    __pass_if_not_null(out_error, TFTPC_OPTION_NOT_FOUND);
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
        free(packet->contents.RWRQ_T.filename);
        free(packet->contents.RWRQ_T.mode);

        for (uint16_t i = 0; i < packet->contents.RWRQ_T.ocount; i++)
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
        free(packet->contents.ERROR_T.msg);
        break;
    case TFTP_OACK:
        for (uint16_t i = 0; i < packet->contents.OACK_T.ocount; i++)
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

    p->opcode = packet_kind;

    p->contents.RWRQ_T.mode = malloc(strlen(mode) + 1);
    strcpy(p->contents.RWRQ_T.mode, mode);

    p->contents.RWRQ_T.filename = malloc(strlen(file_name) + 1);
    strcpy(p->contents.RWRQ_T.filename, file_name);

    p->contents.RWRQ_T.ocount = 0;
    p->contents.RWRQ_T.options = NULL;

    return p;
}

tftpc_packet_t *tftpc_packet_create_data_ack(uint16_t block_no, const uint8_t *opt_data, uint16_t opt_data_size)
{
    tftpc_opcode_t opcode = (opt_data == NULL || opt_data_size == 0) ? TFTP_ACK : TFTP_DATA;

    tftpc_packet_t *packet = (tftpc_packet_t *)malloc(sizeof(tftpc_packet_t));
    packet->opcode = opcode;

    packet->contents.DATACK_T.block = block_no;

    if (opcode == TFTP_DATA)
    {
        packet->contents.DATACK_T.data = malloc(opt_data_size);
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

tftpc_packet_t *tftpc_packet_create_oack()
{
    tftpc_packet_t *packet = (tftpc_packet_t *)malloc(sizeof(tftpc_packet_t));

    packet->opcode = TFTP_OACK;
    packet->contents.OACK_T.options = NULL;
    packet->contents.OACK_T.ocount = 0;

    return packet;
}

tftpc_packet_t *tftpc_packet_create_error(uint16_t error_code, const char *error_message)
{
    if (!error_message)
        return NULL;

    tftpc_packet_t *packet = (tftpc_packet_t *)malloc(sizeof(tftpc_packet_t));

    packet->opcode = TFTP_ERROR;
    packet->contents.ERROR_T.code = error_code;

    packet->contents.ERROR_T.msg = malloc(strlen(error_message + 1));
    strcpy(packet->contents.ERROR_T.msg, error_message);

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
        printf("filename: %s\n", packet->contents.RWRQ_T.filename);
        printf("mode: %s\n", packet->contents.RWRQ_T.mode);
        printf("options:\n");
        for (uint16_t i = 0; i < packet->contents.RWRQ_T.ocount; i++)
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
        printf("msg: %s\n", packet->contents.ERROR_T.msg);
        break;
    case TFTP_OACK:
        printf("options:\n");
        for (uint16_t i = 0; i < packet->contents.OACK_T.ocount; i++)
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
        __pass_if_not_null(out_error, TFTPC_INVALID_ARGUMENT);
        return NULL;
    }

    tftpc_packet_t *packet = (tftpc_packet_t *)malloc(sizeof(tftpc_packet_t));
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
        (packet->contents.RWRQ_T.filename) = __alloc_copy_string(bytes, &idx);
        // mode
        (packet->contents.RWRQ_T.mode) = __alloc_copy_string(bytes, &idx);
        // options
        idx = __a_copy_options_from(&packet->contents.RWRQ_T.options, bytes, &packet->contents.RWRQ_T.ocount, idx, bytes_size);

        if (packet->contents.RWRQ_T.ocount == 0 || packet->contents.RWRQ_T.options == NULL)
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

        packet->contents.ERROR_T.msg = __alloc_copy_string(bytes, &idx);

        break;

    case TFTP_OACK:
        idx = __a_copy_options_from(&packet->contents.OACK_T.options, bytes, &packet->contents.OACK_T.ocount, idx, bytes_size);

        if (packet->contents.OACK_T.ocount == 0)
        {
            free(packet->contents.OACK_T.options);
            packet->contents.OACK_T.options = NULL;

            __pass_if_not_null(out_error, TFTPC_UNEXPECTED_RESULT);
            // non-fatal error
            return packet;
        }

        break;

    default:
        __pass_if_not_null(out_error, TFTPC_INVALID_OPCODE);
        return NULL;
    }

    if (idx != bytes_size)
    {
        if (bytes_size - idx == 1 && bytes[idx++] == 0)
            goto null_byte_appended;

        __pass_if_not_null(out_error, TFTPC_BUFFER_OFFSET_ERROR);
        printf("expected %d, got %d\n", bytes_size, idx);
        return NULL;
    }

null_byte_appended:
    __pass_if_not_null(out_error, TFTPC_SUCCESS);
    return packet;
}

uint8_t *tftpc_bytes_from_packet(const tftpc_packet_t *packet, uint16_t *out_size, tftpc_error_lib_t *out_error)
{
    if (!packet)
    {
        __pass_if_not_null(out_error, TFTPC_INVALID_ARGUMENT);
        return NULL;
    }

    uint16_t size = 2;
    uint16_t idx = 0;
    uint8_t *bytes = malloc(size);

    bytes[idx++] = (packet->opcode >> 8) & 0xFF;
    bytes[idx++] = packet->opcode & 0xFF;

    switch (packet->opcode)
    {
    case TFTP_RRQ:
    case TFTP_WRQ:
    {
        uint16_t filename_len = strlen(packet->contents.RWRQ_T.filename) + 1;
        uint16_t mode_len = strlen(packet->contents.RWRQ_T.mode) + 1;

        size += filename_len + mode_len;
        bytes = realloc(bytes, size);

        memcpy(bytes + idx, packet->contents.RWRQ_T.filename, filename_len);
        idx += filename_len;

        memcpy(bytes + idx, packet->contents.RWRQ_T.mode, mode_len);
        idx += mode_len;

        __a_copy_options_to(&bytes, &idx, &size, packet->contents.RWRQ_T.options, packet->contents.RWRQ_T.ocount);
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
        size += 2 + strlen(packet->contents.ERROR_T.msg) + 1;
        bytes = realloc(bytes, size);

        bytes[idx++] = (packet->contents.ERROR_T.code >> 8) & 0xFF;
        bytes[idx++] = packet->contents.ERROR_T.code & 0xFF;

        memcpy(bytes + idx, packet->contents.ERROR_T.msg, strlen(packet->contents.ERROR_T.msg) + 1);
        idx += strlen(packet->contents.ERROR_T.msg) + 1;
        break;

    case TFTP_OACK:
        __a_copy_options_to(&bytes, &idx, &size, packet->contents.OACK_T.options, packet->contents.OACK_T.ocount);
        break;

    default:
        __pass_if_not_null(out_error, TFTPC_INVALID_OPCODE);
        return NULL;
    }

    if (idx != size)
    {
        __pass_if_not_null(out_error, TFTPC_BUFFER_OFFSET_ERROR);
        return NULL;
    }

    __pass_if_not_null(out_error, TFTPC_SUCCESS);
    __pass_if_not_null(out_size, size);

    return bytes;
}

#endif // implementation

#endif // TFTP_C
