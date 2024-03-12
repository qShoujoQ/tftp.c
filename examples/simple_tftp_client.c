#define TFTPC_CLIENT_IMPLEMENTATION
#include "../addons/tftpc_client.c"

enum { GET, PUT, ERR };

void report_error(const char* message, const char* file, int line) {
#ifdef _WIN32
    char buffer[256];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, WSAGetLastError(), 0, buffer, sizeof(buffer), NULL);
    printf("%s:%d: %s: %s\n", file, line, message, buffer);
#else
    printf("%s:%d: %s: %s\n", file, line, message, strerror(errno));
#endif
}

const char* extract_file_name_from_path(const char* path) {
    const char* file_name = path;
    for (const char* p = path; *p; ++p) {
        if (*p == '/' || *p == '\\') {
            file_name = p + 1;
        }
    }
    return file_name;
}

size_t get_file_size(FILE* file) {
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

int main(int argc, char** argv) {
#ifndef DEBUG
    if (argc < 4) {
        printf("Usage: %s <GET/PUT> <server:port> <file path>\n", argv[0]);
        return 1;
    }

    int operation = strcmp(argv[1], "GET") == 0 ? GET : strcmp(argv[1], "PUT") == 0 ? PUT : ERR;
    const char* server_addr = argv[2];
    const char* file_path = argv[3];

    if (operation == ERR) {
        printf("Invalid operation: %s\n", argv[1]);
        return 1;
    }
#else
    int operation = GET;
    const char* server_addr = "127.0.0.1:69";
    const char* file_path = "migu.jpg";
#endif

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    int udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket == -1) {
        report_error("Error creating socket", __FILE__, __LINE__);
        return 1;
    }

    uint32_t timeout_ms = 3000;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR) {
        report_error("Error setting socket timeout", __FILE__, __LINE__);
        return 1;
    }

    size_t data_size;
    tftpc_error_client_t error;

    if (operation == GET) {
        uint8_t* data = tftpc_client_get(udp_socket, server_addr, file_path, "octet", &data_size, &error);
        
        if (error.code != TFTPC_ERROR_CLIENT_NONE) {
            printf("Error: %s\n", error.message);
            return 1;
        }
        
        FILE* file = fopen(extract_file_name_from_path(file_path), "wb");
        fwrite(data, 1, data_size, file);
        fclose(file);
    } else {

        FILE* file = fopen(file_path, "rb");
        data_size = get_file_size(file);

        uint8_t* data = malloc(data_size);
        fread(data, 1, data_size, file);
        
        fclose(file);
        error = tftpc_client_put(udp_socket, server_addr, extract_file_name_from_path(file_path), "octet", data, data_size);
        
        free(data);
        
        if (error.code != TFTPC_ERROR_CLIENT_NONE) {
            printf("Error: %s\n", error.message);
            return 1;
        }
    }

    printf("%s %s\n", operation == GET ? "Downloaded" : "Uploaded", file_path);

#ifdef _WIN32
    closesocket(udp_socket);
    WSACleanup();
#else
    close(udp_socket);
#endif
    return 0;
}
