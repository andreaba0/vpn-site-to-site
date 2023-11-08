#include "stdlib.h"

class NetworkInterface {
    public:
    int AllocateTunInterface(char *dev, int queues, int *fds);
    int AssignTunIp(char *dev, char *ip);
};