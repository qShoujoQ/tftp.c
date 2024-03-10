#define TFTPC_CLIENT_IMPLEMENTATION
#include "../addons/tftpc_client.c"

int main(void) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket == INVALID_SOCKET) {
        printf("Error creating socket: %d\n", WSAGetLastError());
        return 1;
    }

    int timeout_ms = 3000;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR) {
        printf("Error setting socket timeout: %d\n", WSAGetLastError());
        return 1;
    }

    size_t file_size;
    tftpc_error_client_t e;
    uint8_t* get_data = tftpc_client_get((int)udp_socket, "127.0.0.1:69", "migu.jpg", "octet", &file_size, &e);

    if (e.code != TFTPC_ERROR_CLIENT_NONE) {
        printf("Error getting file: %s\n", e.message);
    } else {
        printf("Downloaded migu.jpg\n");
        FILE* miku = fopen("miku.jpg", "wb");
        fwrite(get_data, 1, file_size, miku);
        fclose(miku);
    }

    free(get_data);

    FILE* source_code = fopen("tftp.c", "rb");
    fseek(source_code, 0, SEEK_END);
    file_size = ftell(source_code);
    fseek(source_code, 0, SEEK_SET);
    uint8_t* put_data = malloc(file_size);
    fread(put_data, 1, file_size, source_code);
    fclose(source_code);

    e = tftpc_client_put((int)udp_socket, "127.0.0.1:69", "tftp.c", "octet", put_data, file_size);
    if (e.code != TFTPC_ERROR_CLIENT_NONE) {
        printf("Error putting file: %s\n", e.message);
    } else {
        printf("Uploaded tftp.c\n");
    }

    free(put_data);

    // cleanup
    closesocket(udp_socket);
    WSACleanup();
    return 0;
}
