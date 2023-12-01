#include "tftpc.h"

#include <winsock2.h>
#include <windows.h>

#include <stdio.h>

char *get_name_from_path(const char *path)
{
    char *name = path;
    char *p = path;
    while (*p != '\0')
    {
        if (*p == '/' || *p == '\\')
        {
            name = p + 1;
        }
        p++;
    }
    return name;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        printf("Usage %s <GET/PUT> <file>\n", argv[0]);
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("WSAStartup failed.\n");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
    {
        printf("socket failed.\n");
        return 1;
    }

    tftpc_client_error_t e;
    uint32_t size;

    const char *method = argv[1];
    const char *name = argv[2];

    if (strcmp(method, "PUT") == 0)
    {
        // read file
        FILE *f = fopen(name, "rb");
        if (f == NULL)
        {
            printf("Failed to open file.\n");
            goto end;
        }

        fseek(f, 0, SEEK_END);
        size = ftell(f);
        fseek(f, 0, SEEK_SET);

        uint8_t *data = malloc(size);
        if (data == NULL)
        {
            printf("Failed to allocate memory.\n");
            goto end;
        }

        fread(data, 1, size, f);
        fclose(f);

        // send file
        e = tftpc_put(sock, "127.0.0.1:69", name, "octet", data, size);
        if (e.error != ERROR_NONE)
        {
            printf("Error: %s\n", e.message);
            goto end;
        }

        printf("Sent %d bytes.\n", size);
        free(data);
    }
    else
    {
        uint8_t *data = tftpc_get(sock, "127.0.0.1:69", name, "octet", &size, &e);
        if (e.error != ERROR_NONE)
        {
            printf("Error: %s\n", e.message);
            goto end;
        }

        printf("Received %d bytes. Saving...\n", size);

        // save to file (create if not exists, overwrite if exists)
        FILE *f = fopen(get_name_from_path(name), "wb");
        if (f == NULL)
        {
            printf("Failed to open file.\n");
            goto end;
        }

        fwrite(data, 1, size, f);
        fclose(f);
        free(data);
    }
end:

    printf("Done.\n");

    closesocket(sock);
    WSACleanup();
    return 0;
}
