/*
 * Replays a classic-pcap Ethernet trace out of an interface with its original timing, so that a
 * root capture on the same device sees real frames. Test tool for the rooted-path experiment:
 * it runs only inside the emulator and is not part of the app.
 *
 *   pcap_inject <interface> <file.pcap>
 */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct global_hdr { uint32_t magic; uint16_t major, minor; int32_t zone; uint32_t sigfigs, snaplen, link; };
struct record_hdr { uint32_t sec, frac, caplen, origlen; };

static void sleep_until(double t0_wall, double t0_trace, double trace_time) {
    double due = t0_wall + (trace_time - t0_trace);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double wait = due - (now.tv_sec + now.tv_nsec / 1e9);
    if (wait > 0.0005) {
        struct timespec ts = { (time_t) wait, (long) ((wait - (time_t) wait) * 1e9) };
        nanosleep(&ts, NULL);
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <interface> <file.pcap>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[2], "rb");
    if (!f) { perror("open"); return 1; }
    struct global_hdr g;
    if (fread(&g, sizeof(g), 1, f) != 1) { fprintf(stderr, "short file\n"); return 1; }
    int nanos = g.magic == 0xA1B23C4D;
    if (g.magic != 0xA1B2C3D4 && !nanos) { fprintf(stderr, "only little-endian classic pcap\n"); return 1; }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 2; }
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = (int) if_nametoindex(argv[1]);
    if (addr.sll_ifindex == 0) { perror("if_nametoindex"); return 3; }

    static uint8_t buf[70000];
    struct record_hdr r;
    long sent = 0, skipped = 0;
    double t0_wall = 0, t0_trace = 0;
    while (fread(&r, sizeof(r), 1, f) == 1) {
        if (r.caplen > sizeof(buf) || fread(buf, 1, r.caplen, f) != r.caplen) break;
        double t = r.sec + r.frac / (nanos ? 1e9 : 1e6);
        if (sent == 0 && skipped == 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            t0_wall = now.tv_sec + now.tv_nsec / 1e9;
            t0_trace = t;
        }
        sleep_until(t0_wall, t0_trace, t);
        if (g.link == 1) {
            if (sendto(sock, buf, r.caplen, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) skipped++;
            else sent++;
        } else if (g.link == 0 || g.link == 108) {
            // Loopback capture: give the IP packet an Ethernet header the tap can strip
            uint8_t frame[14 + sizeof(buf)];
            int ipv6 = r.caplen > 4 && (buf[4] >> 4) == 6;
            memset(frame, 0x02, 12);
            frame[12] = ipv6 ? 0x86 : 0x08;
            frame[13] = ipv6 ? 0xDD : 0x00;
            memcpy(frame + 14, buf + 4, r.caplen - 4);
            if (sendto(sock, frame, 14 + r.caplen - 4, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) skipped++;
            else sent++;
        } else {
            skipped++;
        }
    }
    printf("sent=%ld skipped=%ld\n", sent, skipped);
    return 0;
}
