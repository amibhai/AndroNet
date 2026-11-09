/*
 * Root capture helper.
 *
 * An app process can never open a packet socket, whatever the device's root status, so root
 * mode cannot capture over JNI. NetHunterService starts this binary through su instead. It opens
 * one AF_PACKET socket, drops back to the app's uid (the open socket keeps working), and streams
 * every frame to stdout. It exits as soon as the app stops reading, so a crash of the app can
 * never leave a capture process behind it.
 *
 * Stream format, big-endian: u32 length | u16 ethertype | u8 pkttype | u8 reserved | payload.
 * SOCK_DGRAM strips the link layer, so the payload starts at the IP or ARP header on every
 * interface type (wlan0, rmnet*, eth0) and the same parser serves all of them.
 */
#define _GNU_SOURCE // POLLRDHUP
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_FRAME 65536
#define SOCKET_BUFFER (4 * 1024 * 1024)

static int write_all(int fd, const uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n <= 0) return -1;
        buf += n;
        len -= (size_t) n;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *iface = "any";
    long uid = -1;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--iface") == 0) iface = argv[i + 1];
        else if (strcmp(argv[i], "--uid") == 0) uid = strtol(argv[i + 1], NULL, 10);
    }

    int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return 2;
    }

    int bufsize = SOCKET_BUFFER;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    if (strcmp(iface, "any") != 0) {
        struct sockaddr_ll addr;
        memset(&addr, 0, sizeof(addr));
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_ALL);
        addr.sll_ifindex = (int) if_nametoindex(iface);
        if (addr.sll_ifindex == 0 || bind(sock, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
            perror("bind");
            return 3;
        }
    }

    // Capture needs CAP_NET_RAW only to open the socket, so give everything up before reading.
    if (uid > 0 && (setgid((gid_t) uid) != 0 || setuid((uid_t) uid) != 0)) {
        perror("drop privileges");
        return 4;
    }

    unsigned int loopback = if_nametoindex("lo");
    static uint8_t frame[8 + MAX_FRAME];
    struct pollfd fds[2] = {
        { .fd = sock, .events = POLLIN },
        // A pipe whose reader left reports POLLERR; a socket whose peer left reports only
        // POLLRDHUP, and only when asked. A su implementation may hand over either.
        { .fd = STDOUT_FILENO, .events = POLLRDHUP },
    };
    for (;;) {
        // Waiting here instead of in recvfrom means a quiet network cannot keep this process
        // alive after the app has gone: a closed stdout wakes the poll straight away.
        if (poll(fds, 2, -1) < 0) continue;
        if (fds[1].revents & (POLLERR | POLLHUP | POLLRDHUP)) return 0;
        if (!(fds[0].revents & POLLIN)) continue;

        struct sockaddr_ll from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(sock, frame + 8, MAX_FRAME, 0, (struct sockaddr *) &from, &fromlen);
        if (n < 0) continue;
        if ((unsigned int) from.sll_ifindex == loopback) continue;

        uint32_t length = htonl((uint32_t) n);
        memcpy(frame, &length, 4);
        memcpy(frame + 4, &from.sll_protocol, 2); // already network order
        frame[6] = from.sll_pkttype;
        frame[7] = 0;
        if (write_all(STDOUT_FILENO, frame, 8 + (size_t) n) != 0) return 0;
    }
}
