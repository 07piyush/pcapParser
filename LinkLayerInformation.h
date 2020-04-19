#ifndef LinkLayerInformation_H
#define LinkLayerInformation_H

#include<iostream>

using namespace std;

struct LinkLayerInformation{
	
	 unsigned char destination[6],
		       source[6];
	unsigned short connectionType;

	LinkLayerInformation() {
		source[0] = '\0';
		destination[0] = '\0';
		connectionType = 0;
	 }
	
	~LinkLayerInformation() { }
    
};


#endif //LinkLayerInformation
