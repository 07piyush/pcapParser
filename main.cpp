#include <iostream>
#include <fstream>
#include "includes/pcap/PCapParser.h"

using namespace std;

int main()
{
    char fileName[] = "/home/sharma7/Documents/PcapFiles/samplePCAP.pcap";
    int fileNameSize = sizeof(fileName)/sizeof(char);
    /*

  myfile.close();*/
    PCapParser parser;
    parser.parse(fileName, fileNameSize);


    return 0;
}
