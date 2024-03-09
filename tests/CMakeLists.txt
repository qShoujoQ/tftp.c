add_executable (tftpc_test test.c)
add_executable (tftpc_client_test test_client.c)

if (WIN32)
   target_link_libraries (tftpc_test ws2_32)
   target_link_libraries (tftpc_client_test ws2_32)
endif ()