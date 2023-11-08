#include "ip_packet.h"
#include <string.h>

unsigned char IpPacket::getVersion(unsigned char *packet)
{
    return (packet[0] >> 4) & 0x0f;
}
unsigned char IpPacket::getHeaderLength(unsigned char *packet)
{
    return packet[0] & 0x0f;
}
unsigned char IpPacket::getTTL(unsigned char *packet)
{
    return packet[8];
}
unsigned char IpPacket::getProtocol(unsigned char *packet)
{
    return packet[9];
}
unsigned short IpPacket::getChecksum(unsigned char *packet)
{
    return (packet[10] << 8) | packet[11];
}
unsigned int IpPacket::getSourceIp(unsigned char *packet)
{
    return (packet[12] << 24) | (packet[13] << 16) | (packet[14] << 8) | packet[15];
}
unsigned int IpPacket::getDestinationIp(unsigned char *packet)
{
    return (packet[16] << 24) | (packet[17] << 16) | (packet[18] << 8) | packet[19];
}
unsigned char *IpPacket::getData(unsigned char *packet)
{
    return packet + getHeaderLength(packet) * 4;
}
unsigned short IpPacket::getLength(unsigned char *packet)
{
    return (packet[2] << 8) | packet[3];
}

void IpPacket::setVersion(unsigned char version, unsigned char *packet)
{
    packet[0] = (packet[0] & 0x0f) | (version << 4);
}
void IpPacket::setSourceIp(unsigned int ip, unsigned char *packet)
{
    packet[12] = (ip >> 24) & 0xff;
    packet[13] = (ip >> 16) & 0xff;
    packet[14] = (ip >> 8) & 0xff;
    packet[15] = ip & 0xff;
}
void IpPacket::setDestinationIp(unsigned int ip, unsigned char *packet)
{
    packet[16] = (ip >> 24) & 0xff;
    packet[17] = (ip >> 16) & 0xff;
    packet[18] = (ip >> 8) & 0xff;
    packet[19] = ip & 0xff;
}
void IpPacket::setChecksum(unsigned short checksum, unsigned char *packet)
{
    packet[10] = (checksum >> 8) & 0xff;
    packet[11] = checksum & 0xff;
}
unsigned short IpPacket::calculateChecksum(unsigned char *packet)
{
    unsigned int sum = 0;
    unsigned short length = IpPacket::getHeaderLength(packet) * 4;
    for (int i = 0; i < length; i += 2)
    {
        if(i==10) {
            sum += 0;
        } else {
            sum += (packet[i] << 8) | packet[i + 1];
        }
    }
    while (sum >> 16)
    {
        sum = (sum & 0x000000000000ffff) + (sum >> 16);
    }
    return ~sum;
}
unsigned char IcmpPacket::getType(unsigned char *packet)
{
    return packet[20];
}
unsigned char IcmpPacket::getCode(unsigned char *packet)
{
    return packet[21];
}
unsigned short IcmpPacket::getChecksum(unsigned char *packet)
{
    return (packet[22] << 8) | packet[23];
}
unsigned short IcmpPacket::getIdentifier(unsigned char *packet)
{
    return (packet[24] << 8) | packet[25];
}
unsigned short IcmpPacket::getSequenceNumber(unsigned char *packet)
{
    return (packet[26] << 8) | packet[27];
}
unsigned char *IcmpPacket::getData(unsigned char *packet)
{
    return packet + 28;
}
unsigned short IcmpPacket::getLength(unsigned char *packet)
{
    return IpPacket::getLength(packet) - IpPacket::getHeaderLength(packet) * 4;
}
void IcmpPacket::setType(unsigned char type, unsigned char *packet)
{
    packet[20] = type;
}
void IcmpPacket::setCode(unsigned char code, unsigned char *packet)
{
    packet[21] = code;
}
void IcmpPacket::setChecksum(unsigned short checksum, unsigned char *packet)
{
    packet[22] = (checksum >> 8) & 0xff;
    packet[23] = checksum & 0xff;
}
void IcmpPacket::setIdentifier(unsigned short identifier, unsigned char *packet)
{
    packet[24] = (identifier >> 8) & 0xff;
    packet[25] = identifier & 0xff;
}
void IcmpPacket::setSequenceNumber(unsigned short sequenceNumber, unsigned char *packet)
{
    packet[26] = (sequenceNumber >> 8) & 0xff;
    packet[27] = sequenceNumber & 0xff;
}
void IcmpPacket::setData(unsigned char *data, unsigned char *packet, unsigned short length)
{
    memcpy(packet + 28, data, length);
}
unsigned short IcmpPacket::calculateChecksum(unsigned char *packet)
{
    unsigned int sum = 0;
    unsigned short length = IcmpPacket::getLength(packet);
    unsigned short ipLength = IpPacket::getLength(packet);
    for (int i = IpPacket::getHeaderLength(packet)*4; i < ipLength; i += 2)
    {
        if(i==22) {
            sum += 0;
        } else {
            sum += (packet[i] << 8) | packet[i + 1];
        }
    }
    while (sum >> 16)
    {
        sum = (sum & 0x000000000000ffff) + (sum >> 16);
    }
    return ~sum;
}