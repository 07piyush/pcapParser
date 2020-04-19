#ifndef TransportLayerInformation_H
#define TransportLayerInformation_H

#include<iostream>

using namespace std;

enum protocolType {TCP, UDP, OTHER};

struct TransportLayerInformation{
	
	protocolType protocol;
	unsigned short sourcePort, destinationPort;

	TransportLayerInformation() { }
};


#endif //TransportLayerInformation_H
