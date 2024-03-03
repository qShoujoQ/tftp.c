add_executable (tftpc_test test.c)

if (WIN32)
   target_link_libraries (tftpc_test ws2_32)
endif ()