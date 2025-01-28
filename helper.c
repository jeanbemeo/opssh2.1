#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

extern int errno;

// Fungsi untuk mengirim data melalui socket
int send_packet(int sock, const char *data, size_t len) {
    int result = send(sock, data, len, 0);
    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Socket tidak siap, coba lagi nanti
            usleep(1000); // Tunggu sebentar sebelum mencoba lagi
            return send_packet(sock, data, len);
        }
        perror("send failed");
        return -1;
    }
    return result;
}

// Fungsi untuk melakukan handshake SSH
int perform_ssh_handshake(int sock) {
    // Simulasi handshake SSH
    char ssh_msg[] = "SSH Handshake message";
    if (send_packet(sock, ssh_msg, sizeof(ssh_msg)) < 0) {
        return -1;
    }
    return 0;
}

// Fungsi untuk mencoba kondisi balapan (race condition)
int attempt_race_condition(int sock, double parsing_time, unsigned long glibc_base) {
    // Simulasi eksploitasi dengan base glibc
    printf("Race condition attempt with glibc base 0x%lx\n", glibc_base);
    if (parsing_time < 0.1) {
        return 1;  // Simulasi eksploitasi berhasil
    }
    return 0;
}
