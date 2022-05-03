#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <stdint.h>

#include <net/if.h> // ifreq
#include <linux/if_tun.h> // IFF_TUN, IFF_NO_PI
#include <linux/if_arp.h>

#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tiny-AES-c/aes.h"
#include "libeddsa/lib/eddsa.h"

#define BUFFLEN (65536)
#define ADDR_LENGTH_INET (8)

int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0) {
        fprintf(stderr, "open(/dev/net/tun)\n");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (*dev) {
       strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
       close(fd);
       fprintf(stderr, "TUNSETIFF\n");
       return -1;
    }
    strncpy(dev, ifr.ifr_name, IFNAMSIZ);

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_mtu = 1400;
    int fd_netdevice;
    fd_netdevice = socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl(fd_netdevice, SIOCSIFMTU, &ifr) < 0) {
        fprintf(stderr, "SIOCSIFMTU\n");
        close(fd);
        close(fd_netdevice);
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if ((err = ioctl(fd_netdevice, SIOCGIFFLAGS, &ifr)) < 0) {
        close(fd);
        close(fd_netdevice);
        fprintf(stderr, "SIOCGIFFLAGS\n");
        return -1;
    }
    ifr.ifr_flags |= IFF_UP;
    if ((err = ioctl(fd_netdevice, SIOCSIFFLAGS, &ifr)) < 0) {
        close(fd);
        close(fd_netdevice);
        fprintf(stderr, "SIOCSIFFLAGS\n");
        return -1;
    }
    return fd;
}

// <if_name> <local_port> <remote_addr> <remote_port>
int main(int argc, char ** argv) {
    char dev_name[IFNAMSIZ];
    char buf[BUFFLEN];
    fd_set rfds;
    fd_set wfds;
    struct timeval tv;
    int retval;
    int sockfd;
    int tunfd;
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    int local_port = 0;
    int remote_port = 0;
    size_t slen = sizeof(struct sockaddr_in);

    if (argc < 5) {
        fprintf(stderr, "argc\n");
        return 1;
    }
    strncpy(dev_name, argv[1], IFNAMSIZ);
    sscanf(argv[2], "%d", &local_port);
    sscanf(argv[4], "%d", &remote_port);
    if ((tunfd = tun_alloc(dev_name)) < 0) {
        fprintf(stderr, "tun_alloc\n");
        return 1;
    }

    sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    local_addr.sin_family = AF_INET;  
    local_addr.sin_addr.s_addr = inet_addr("0.0.0.0");  
    local_addr.sin_port = htons(local_port);
    bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(argv[3]);
    remote_addr.sin_port = htons(remote_port);

    while (1) {
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        FD_SET(tunfd, &rfds);
        int maxfd;
        maxfd = sockfd > tunfd ? sockfd : tunfd;
        select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (FD_ISSET(sockfd, &rfds)) {
            size_t len_received, len_written;
            len_received = recvfrom(sockfd, buf, BUFFLEN, MSG_DONTWAIT, NULL, 0);
            if (len_received < 0) {
                fprintf(stderr, "recvfrom(sockfd) failed\n");
            } else {
                len_written = write(tunfd, buf, len_received);
                if (len_written < 0) {
                    fprintf(stderr, "write(tunfd) failed\n");
                } else if (len_written < len_received) {
                    fprintf(stderr, "Only %ld/%ld bytes written\n", len_written, len_received);
                }
            }
        }
        if (FD_ISSET(tunfd, &rfds)) {
            size_t len_read, len_sent;
            len_read = read(tunfd, buf, BUFFLEN);
            if (len_read < 0) {
                fprintf(stderr, "read(tunfd) failed\n");
            } else {
                len_sent = sendto(sockfd, buf, len_read, MSG_DONTWAIT, (struct sockaddr*)&remote_addr, slen);
                if (len_sent < 0) {
                    fprintf(stderr, "sendto(sockfd) failed\n");
                } else if (len_sent < len_read) {
                    fprintf(stderr, "Only %ld/%ld bytes sent\n", len_sent, len_read);
                }
            }
        }
    }
}
