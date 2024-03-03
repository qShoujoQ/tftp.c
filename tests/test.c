#define TFTPC_IMPLEMENTATION
#include "../tftp.c"

int main(void)
{
   char data[] = "beeeer ~~";

   // tftpc_packet_t *packet = tftpc_packet_create_data_ack(69, data, strlen(data) + 1);
   // tftpc_packet_t *packet = tftpc_packet_create_request(TFTP_RRQ, "test", "octet");
   tftpc_packet_t *packet = tftpc_packet_create_error(1, "test");

   // tftpc_packet_add_option(packet, "tsize", "420");
   // tftpc_packet_add_option(packet, "blksize", "2137");

   printf("Old packet:\n");
   tftpc_packet_print(packet);
   printf("\n");

   tftpc_error_lib_t e;
   uint16_t size;
   // uint8_t           bytes[] = { 0x00, 0x01, 't', 'e', 's', 't', 0, 'a', 's', 'c', 'i', 'i', 0, 'd', 'u', 'p', 'a', 0, 't', 's', 'i', 'z', 'e', 0, '0', 0, 'X', 'D', 0 };
   // size = 29;
   // e    = TFTPC_SUCCESS;
   uint8_t *bytes = tftpc_bytes_from_packet(packet, &size, &e);

   tftpc_packet_free(packet);
   packet = NULL;

   printf("Packet bytes: ");
   __print_bytes_hex(bytes, size);
   printf("\n");

   if (e != TFTPC_SUCCESS)
   {
      tftpc_error_print(ERROR_KIND_LIB, e, "serializing error");
      if (e != TFTPC_UNEXPECTED_RESULT)
         return 1;
      else
         __print_bytes_hex(bytes, size);
   }

   tftpc_packet_t *new_packet = tftpc_packet_from_bytes(bytes, size, &e);

   if (e != TFTPC_SUCCESS)
   {
      tftpc_error_print(ERROR_KIND_LIB, e, "deserializing error");
      return 1;
   }

   printf("Reconstructed packet:\n");
   tftpc_packet_print(new_packet);
   printf("\n");

   tftpc_packet_free(new_packet);

   return 0;
}
