add_library(tftpclient STATIC tftpc.c)
if (WIN32)
   target_link_libraries (tftpclient ws2_32)
endif ()

add_executable (test_tftpcc test_tftpcc.c)
if (WIN32)
   target_link_libraries (tftpclient ws2_32)
endif ()
target_link_libraries (test_tftpcc tftpclient)

file(COPY tftpc.h DESTINATION ${CMAKE_SOURCE_DIR}/lib/client)
file(COPY ${CMAKE_BINARY_DIR}/addons/libtftpclient.a DESTINATION ${CMAKE_SOURCE_DIR}/lib/client)
