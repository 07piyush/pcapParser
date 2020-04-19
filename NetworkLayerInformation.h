#ifndef NetworkLayerInformation_H
#define NetworkLayerInformation_H

#include "IPv6.h"
#include <arpa/inet.h>

using namespace std;


union IPaddress{
		unsigned int ipv4;
		IPv6 ipv6;
};


struct NetworkLayerInformation{

	IPaddress source, destination;
	unsigned char protocol;	
	bool isIPv4;

	void printAddresses() {
		if(isIPv4){
			//source.ipv4 = ntohl(source.ipv4);
			//destination.ipv4 = ntohl(destination.ipv4); 
			unsigned char *temporaryPointer = (unsigned char *)&source.ipv4;
			printf("Source IP: "); for(int i=0; i<4; i++) printf("%d:", temporaryPointer[i]);
			printf("\n");
			temporaryPointer = (unsigned char *)&destination.ipv4;
			printf("Destination IP: "); for(int i=0; i<4; i++) printf("%d:", temporaryPointer[i] );
			printf("\n");
		}
		else{
			printf("Source IP: "); for(int i=0; i<16; i+=2) printf("%x%x:", source.ipv6.address[i], 												     source.ipv6.address[i+1]);
			printf("\n");
			printf("Destination IP: "); for(int i=0; i<16; i+=2) printf("%x%x:", destination.ipv6.address[i], 												     destination.ipv6.address[i+1]);
			printf("\n");
		}
	}
	

	NetworkLayerInformation() {	}

	~NetworkLayerInformation(){  }

};


#endif //NetworkLayerInformation
