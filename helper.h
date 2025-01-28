#ifndef HELPER_H
#define HELPER_H

#include <stdint.h>
#include <stdlib.h>

// Function declarations
int setup_connection(const char *ip, int port);
void send_packet(int sock, unsigned char packet_type, const unsigned char *data, size_t len);
void prepare_heap(int sock);
void create_fake_file_structure(unsigned char *data, size_t size, uint64_t glibc_base);
void time_final_packet(int sock, double *parsing_time);
double measure_response_time(int sock, int error_type);

extern uint64_t GLIBC_BASES[];
extern int NUM_GLIBC_BASES;

#endif
