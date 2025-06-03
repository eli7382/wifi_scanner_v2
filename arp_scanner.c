#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/select.h>

#define MAX_DEVICES 256

struct device {
    char ip[16];
    char mac[18];
};

/* Helper to print MAC address */
static void mac_to_str(unsigned char *mac, char *out) {
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int main(int argc, char *argv[]) {
    struct ifaddrs *ifaddr, *ifa;
    char iface[IFNAMSIZ] = "";
    struct in_addr my_ip = {0}, netmask = {0};
    unsigned char my_mac[6];
    int sock;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }

    /* Find the first non-loopback interface with an IPv4 address */
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
            !(ifa->ifa_flags & IFF_LOOPBACK)) {
            strncpy(iface, ifa->ifa_name, IFNAMSIZ - 1);
            my_ip = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            netmask = ((struct sockaddr_in*)ifa->ifa_netmask)->sin_addr;
            break;
        }
    }
    freeifaddrs(ifaddr);

    if (!iface[0]) {
        fprintf(stderr, "No suitable interface found\n");
        return 1;
    }

    /* Get MAC address of the interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(sock);
        return 1;
    }
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);

    /* Raw socket for ARP */
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_ll sock_addr;
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sll_ifindex = if_nametoindex(iface);
    sock_addr.sll_family = AF_PACKET;
    sock_addr.sll_halen = 6;
    memset(sock_addr.sll_addr, 0xff, 6); /* broadcast */

    unsigned char buffer[42];
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct ether_arp *arp = (struct ether_arp *)(buffer + ETH_HLEN);

    /* Prepare constant parts of the ARP request */
    memset(buffer, 0, sizeof(buffer));
    memset(eth->h_dest, 0xff, ETH_ALEN);
    memcpy(eth->h_source, my_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(arp->arp_sha, my_mac, ETH_ALEN);
    memcpy(arp->arp_spa, &my_ip.s_addr, 4);
    memset(arp->arp_tha, 0x00, ETH_ALEN);

    struct device devices[MAX_DEVICES];
    int dev_count = 0;

    uint32_t base = ntohl(my_ip.s_addr & netmask.s_addr);
    uint32_t broadcast = ntohl(my_ip.s_addr | ~netmask.s_addr);

    for (uint32_t addr = base + 1; addr < broadcast && dev_count < MAX_DEVICES; addr++) {
        if (addr == ntohl(my_ip.s_addr)) continue; /* skip own ip */
        struct in_addr target_ip = { htonl(addr) };
        memcpy(arp->arp_tpa, &target_ip.s_addr, 4);

        if (sendto(sock, buffer, sizeof(buffer), 0,
                   (struct sockaddr*)&sock_addr, sizeof(sock_addr)) == -1) {
            perror("sendto");
            continue;
        }

        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000; /* 200 ms */

        if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
            unsigned char recvbuf[60];
            ssize_t len = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
            if (len >= 42) {
                struct ether_arp *r_arp = (struct ether_arp *)(recvbuf + ETH_HLEN);
                if (ntohs(r_arp->ea_hdr.ar_op) == ARPOP_REPLY &&
                    memcmp(r_arp->arp_spa, &target_ip.s_addr, 4) == 0) {
                    char ip_str[16];
                    char mac_str[18];
                    inet_ntop(AF_INET, r_arp->arp_spa, ip_str, sizeof(ip_str));
                    mac_to_str(r_arp->arp_sha, mac_str);
                    strncpy(devices[dev_count].ip, ip_str, sizeof(devices[dev_count].ip));
                    strncpy(devices[dev_count].mac, mac_str, sizeof(devices[dev_count].mac));
                    dev_count++;
                }
            }
        }
    }

    close(sock);

    /* Write JSON output */
    FILE *out = fopen("scanner/devices.json", "w");
    if (!out) {
        perror("fopen");
        return 1;
    }

    fprintf(out, "[\n");
    for (int i = 0; i < dev_count; i++) {
        fprintf(out, "  {\"ip\": \"%s\", \"mac\": \"%s\"}%s\n",
                devices[i].ip, devices[i].mac,
                (i == dev_count - 1) ? "" : ",");
    }
    fprintf(out, "]\n");
    fclose(out);

    printf("Found %d device(s). Results written to scanner/devices.json\n", dev_count);
    return 0;
}
