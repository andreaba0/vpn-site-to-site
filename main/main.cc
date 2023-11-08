#include "stdio.h"
#include "ip_packet.h"
#include "network_interface.h"
#include "string.h"
#include "unistd.h"

int main() {
    NetworkInterface networkInterface;
    int fds[1];
    char dev[] = "tun0";
    int fd = networkInterface.AllocateTunInterface(dev, 1, fds);

    printf("fd: %d\n", fd);

    if(fd<0) return 1;

    char ip[] = "10.114.0.16";
    int status = networkInterface.AssignTunIp(dev, ip);

    unsigned char buffer[1500];
    unsigned char icmpEchoReply[1500];

    while (1) {
        int nread = read(fd, buffer, sizeof(buffer));
        if(nread<0) continue;
        if(IpPacket::getVersion(buffer) != 4) continue;
        if(static_cast<int>(IpPacket::getProtocol(buffer))!=IpProtocol::ICMP) continue;
        if(static_cast<int>(IcmpPacket::getType(buffer)) != IcmpType::ECHO_REQUEST) continue;
        printf("Received ICMP packet\n");
        printf("Source IP: %d.%d.%d.%d\n", (IpPacket::getSourceIp(buffer) >> 24) & 0xff, (IpPacket::getSourceIp(buffer) >> 16) & 0xff, (IpPacket::getSourceIp(buffer) >> 8) & 0xff, IpPacket::getSourceIp(buffer) & 0xff);
        printf("Destination IP: %d.%d.%d.%d\n", (IpPacket::getDestinationIp(buffer) >> 24) & 0xff, (IpPacket::getDestinationIp(buffer) >> 16) & 0xff, (IpPacket::getDestinationIp(buffer) >> 8) & 0xff, IpPacket::getDestinationIp(buffer) & 0xff);
        printf("ICMP sequence number: %d\n", IcmpPacket::getSequenceNumber(buffer));
        printf("\n");
        memset(icmpEchoReply, 0, sizeof(icmpEchoReply));
        memcpy(icmpEchoReply, buffer, nread);
        IcmpPacket::setType(IcmpType::ECHO_REPLY, icmpEchoReply);
        IcmpPacket::setChecksum(IcmpPacket::calculateChecksum(icmpEchoReply), icmpEchoReply);
        IpPacket::setSourceIp(IpPacket::getDestinationIp(buffer), icmpEchoReply);
        IpPacket::setDestinationIp(IpPacket::getSourceIp(buffer), icmpEchoReply);
        IpPacket::setChecksum(IpPacket::calculateChecksum(icmpEchoReply), icmpEchoReply);
        write(fd, icmpEchoReply, nread);
    }
    
    return 0;
}