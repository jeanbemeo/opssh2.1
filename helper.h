#ifndef HELPER_H
#define HELPER_H

int send_packet(int sock, const char *data, size_t len);
int perform_ssh_handshake(int sock);
int attempt_race_condition(int sock, double parsing_time, unsigned long glibc_base);

#endif
