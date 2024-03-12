add_executable (client_example simple_tftp_client.c)
if (WIN32)
    target_link_libraries (client_example wsock32 ws2_32)
endif (WIN32)