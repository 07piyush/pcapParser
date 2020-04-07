#ifndef NetworkLayerInformation_H
#define NetworkLayerInformation_H

#include "IPv6.h"

using namespace std;


union IPaddress{ 
		unsigned int ipv4;
		IPv6 ipv6;
};



struct NetworkLayerInformation{

	IPaddress source, destination;
	unsigned int protocol;	
	bool isIPv4;
	

	NetworkLayerInformation() {	}

	~NetworkLayerInformation(){	}

};


#endif //NetworkLayerInformation
