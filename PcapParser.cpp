#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <cstdio>
#include <arpa/inet.h>
#include "includes/pcap/PCapParser.h"

using namespace std;


std::ifstream::pos_type PCapParser::getFileSize(const char* fileName)
{
    std::ifstream in(fileName, std::ifstream::ate | std::ifstream::binary);
    return in.tellg(); 
}

FileInformation PCapParser::parse(char fileName[], int lengthOfFileName){

    pcapFileName = fileName;
    
    unsigned int fileTypeMagicNumber, 
		 packetCount = 0;

    unsigned int fileSize = getFileSize(fileName);

    cout<<fileSize<<endl;

    ifstream myfile (fileName, ifstream::binary);
    myfile.read ((char *)&fileTypeMagicNumber, 4);
    cout<<std::hex<<ntohl(fileTypeMagicNumber)<<endl;


    myfile.seekg(20, ios::cur);// global header ends here

    while(myfile.good()){ // while EOF is not encountered, do following for each packet
        //1. Packet Header
            //a. skip 8(4+4) bytes and then,
            //b. read incl_len.
            //c. skip next 4 bytes, packet header ends.
        //2. Packet Data
            //a. get source mac first 6 bytes.
            //b. get destination mac
	
	PacketInformation packetInfo;

	packetCount++;
        myfile.seekg(8, ios::cur); // a. skip 8(4+4) bytes and then,

        unsigned int packetLength;
        myfile.read((char *)&packetLength, 4); // b. read incl_len.
	//cout<<"incl_len: "<<(int)packetLength<<endl<<endl;
	
        myfile.seekg(4, ios::cur); // c skip next 4 bytes, packet header ends.

        //a. get destination mac first 6 bytes.
        myfile.read((char *) &packetInfo.theDataLinkLayer.destination, 6);

        //a. get source mac 6 bytes.
        myfile.read((char *) &packetInfo.theDataLinkLayer.source, 6);

        
        myfile.read((char *) &packetInfo.theDataLinkLayer.connectionType, 2); //Ethernet header ends
	
	unsigned int sourceIP, destinationIP;
	

	if(ntohl(packetInfo.theDataLinkLayer.connectionType) == 0x8000000){

		packetInfo.theNetworkLayer.isIPv4 = true;

		fileInfo.IPv4PacketsCount++;

		myfile.seekg(9, ios::cur); // skip according to IPv4 header
        	
        	myfile.read((char *)&packetInfo.theNetworkLayer.protocol, 1);

        	myfile.seekg(2, ios::cur); // skip according to IPv4 header

        	myfile.read((char *) &packetInfo.theNetworkLayer.source.ipv4, 4);

        	myfile.read((char *) &packetInfo.theNetworkLayer.destination.ipv4, 4); // IP header ends here

		fileInfo.ipv4Count[packetInfo.theNetworkLayer.source.ipv4]++;
		fileInfo.ipv4Count[packetInfo.theNetworkLayer.destination.ipv4]++;

	}
	else if(ntohl(packetInfo.theDataLinkLayer.connectionType) == 0x86DD0000){

		//packetInfo.theNetworkLayer.source = new unsigned char[17];
		//packetInfo.theNetworkLayer.destination = new unsigned char[17];
		packetInfo.theNetworkLayer.isIPv4 = false;

		fileInfo.IPv6PacketsCount++;
		myfile.seekg(64, ios::cur);
	}


        unsigned short sourcePort; // Transport layer Data unit header.
        myfile.read((char *)&sourcePort, 2);

        unsigned short destinationPort;
        myfile.read((char *)&destinationPort, 2);

	unsigned short int dataLen;
        myfile.read((char *)&dataLen, 2);

	myfile.seekg(2, ios::cur);//Transport layer Data unit header ends
	
	unsigned int skipBy = packetLength - 42;
	
	myfile.seekg(skipBy, ios::cur);

if(packetCount > 88 && packetCount < 100){

    cout<<"**** Packet #"<<std::dec<<packetCount<<" ****"<<endl;
	
    cout<<"packetLength: "<<packetLength<<endl;
    
    for(int i=0; i<6; i++ ) printf("%x ", packetInfo.theDataLinkLayer.source[i]); cout<<" :MACsource"<<endl;
    for(int i=0; i<6; i++ ) printf("%x ", packetInfo.theDataLinkLayer.destination[i]); cout<<" :MACdestination"<<endl;
    
    //cout<<std::hex<<ntohl(connectionType)<<" :connectionType"<<endl;
    //cout<<dec<< ntohl( sourceIP ) <<" :sourceIP"<<endl;	

   // for(int i=0; i<4; i++) printf("%d ", packetInfo.theNetworkLayer.source[i]); cout<<" :sourceIP"<<endl;

    //printf("%d ", protocol); cout<<" :protocol"<<endl;
    //cout<< ntohl( destinationIP ) <<" :destinationIP"<<endl;	

   // for(int i=0; i<4; i++) printf("%d ", packetInfo.theNetworkLayer.destination[i]); cout<<" :destinationIP"<<endl;

    printf("%x ", ntohl(sourcePort) ); cout<<" :sourcePort"<<endl;
    printf("%x ", ntohl(destinationPort) ); cout<<" :destinationPort"<<endl<<endl<<endl;

}
    
    	}

    myfile.close();
    	cout<<"Total IPv4 packets: "<<fileInfo.IPv4PacketsCount<<endl;
	
    for(pair<unsigned int, unsigned int> keyValue : fileInfo.ipv4Count)
	cout<<keyValue.first<<"->"<<keyValue.second<<endl;

}

PCapParser::PCapParser(){
   
}

void PCapParser::createCSVfile(){

}

void PCapParser::writeInfoToCSV(){ 

}

void PCapParser::printFileInformationTillNow(){

   
}

void PCapParser::printPacketInformation(){
   

}

