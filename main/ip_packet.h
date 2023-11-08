class IpPacket {
    public:
        static unsigned char getVersion(unsigned char *packet);
        static unsigned char getHeaderLength(unsigned char *packet);
        static unsigned char getTTL(unsigned char *packet);
        static unsigned char getProtocol(unsigned char *packet);
        static unsigned short getChecksum(unsigned char *packet);
        static unsigned int getSourceIp(unsigned char *packet);
        static unsigned int getDestinationIp(unsigned char *packet);
        static unsigned char *getData(unsigned char *packet);
        static unsigned short getLength(unsigned char *packet);

        static void setVersion(unsigned char version, unsigned char *packet);
        static void setSourceIp(unsigned int ip, unsigned char *packet);
        static void setDestinationIp(unsigned int ip, unsigned char *packet);
        static void setChecksum(unsigned short checksum, unsigned char *packet);

        static unsigned short calculateChecksum(unsigned char *packet);
};

class IcmpPacket : public IpPacket {
    public:
        static unsigned char getType(unsigned char *packet);
        static unsigned char getCode(unsigned char *packet);
        static unsigned short getChecksum(unsigned char *packet);
        static unsigned short getIdentifier(unsigned char *packet);
        static unsigned short getSequenceNumber(unsigned char *packet);
        static unsigned char *getData(unsigned char *packet);
        static unsigned short getLength(unsigned char *packet);

        static void setType(unsigned char type, unsigned char *packet);
        static void setCode(unsigned char code, unsigned char *packet);
        static void setChecksum(unsigned short checksum, unsigned char *packet);
        static void setIdentifier(unsigned short identifier, unsigned char *packet);
        static void setSequenceNumber(unsigned short sequenceNumber, unsigned char *packet);
        static void setData(unsigned char *data, unsigned char *packet, unsigned short length);

        static unsigned short calculateChecksum(unsigned char *packet);
};

enum IpProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ESP = 50,
    AH = 51,
};

enum IcmpType {
    ECHO_REPLY = 0,
    ECHO_REQUEST = 8,
    ECHO_REDIRECT = 5,
    DESTINATION_UNREACHABLE = 3,
    TIME_EXCEEDED = 11,
    PARAMETER_PROBLEM = 12,
};