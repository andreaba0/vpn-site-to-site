#include "network_interface.h"
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <stdio.h>
#include <stddef.h>
#include <arpa/inet.h>
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <asm/types.h>
#include <linux/if_ether.h>
#endif

#define ifreq_offsetof(x) offsetof(struct ifreq, x)

int NetworkInterface::AllocateTunInterface(char *dev, int queues, int *fds)
{
    struct ifreq ifr;
    int fd, err;

    if (!dev)
    {
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (*dev)
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        return fd;
    }
    err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err)
    {
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    return fd;
}

int NetworkInterface::AssignTunIp(char *dev, char *ip)
{
    struct ifreq ifr;
    struct ifreq ifr2;
    struct sockaddr_in sai;
    struct sockaddr_in bsai;
    int sockfd; /* socket fd we use to manipulate stuff with */

    char *p;
    char *b;

    char netmask[] = "255.255.240.0";

    /* Create a channel to the NET kernel. */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* get interface name */
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    strncpy(ifr2.ifr_name, dev, IFNAMSIZ);

    memset(&sai, 0, sizeof(struct sockaddr_in));
    sai.sin_family = AF_INET;
    sai.sin_port = 0;
    sai.sin_addr.s_addr = inet_addr(ip);

    memset(&bsai, 0, sizeof(struct sockaddr_in));
    bsai.sin_family = AF_INET;
    bsai.sin_port = 0;
    bsai.sin_addr.s_addr = inet_addr(netmask);

    p = (char *)&sai;
    b = (char *)&bsai;

    memcpy((((char *)&ifr + ifreq_offsetof(ifr_addr))), p,
           sizeof(struct sockaddr));
    memcpy((((char *)&ifr2 + ifreq_offsetof(ifr_netmask))), b,
           sizeof(struct sockaddr));

    ioctl(sockfd, SIOCSIFADDR, &ifr);
    ioctl(sockfd, SIOCSIFNETMASK, &ifr2);

        
    ifr2.ifr_flags = IFF_UP | IFF_RUNNING;
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    ioctl(sockfd, SIOCSIFFLAGS, &ifr);
    ioctl(sockfd, SIOCSIFFLAGS, &ifr2);
    close(sockfd);
    return 0;
}