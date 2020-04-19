#ifndef PCapParser_H
#define PCapParser_H


#include "FileInformation.h"
#include "PacketInformation.h"
#include "PacketsInformation/IPv6.h"
#include <fstream>
#include <map>

/**********************************************************************************

* This file is part of c++ assignment 2 and assignment 3.
* This file is declaration of class "PCapParser".
* This class will be accessed by another class "pcap" declared in 'pcap.h' file.
* Objective of this class is to parse a pacap file, and retrieve information of each packet in it.
* also to write derived information into a .csv file.
* This class uses three structure to store necessary information from each layer of TCP/IP model.
* Following structure are used for specific layer:

		'LinkLayerInformation'		: defined in LinkLayerInformation.h
		'NetworkLayerInformation'	: defined in NetworkLayerInformation.h
		'TransportLayerInformation'	: defined in TransportLayerInformation.h

* Details to each of these structures are well explained in their respective files.
*
*******************************************************************************/

class PCapParser{

	public:
        FileInformation parse(char fileName[], int length);
        PCapParser() {}

	~PCapParser() {
		delete[] csvIPinfo;
		delete[] csvFileInfo;
	}
    private:
	std::ifstream::pos_type getFileSize(const char *fileName);
        void createCSVfile();
        void writeInfoToCSV(PacketInformation packetInfo);
	void writeInfoToCSV(FileInformation fileInfo);
        void printFileInformationTillNow( FileInformation fileInfo );
        void printPacketInformation();

	private:
	    const char *pcapFileName;   // will be set by either listing files in a folder, or by inotify.
	    char *csvFileInfo, *csvIPinfo; // will be set by parse method.
	    map<IPv6, unsigned int> ipv6Count;
	    map<unsigned int, unsigned int> ipv4Count; 
	    FileInformation fileInfo;

};




#endif
