#include "pcap/PCapParser.h"
#include <vector>

#ifndef Engine_H
#define Engine_H


/******************************************************************************
* This file is part of c++ assignment 2 and assignment 3.
* This file is declaration of class "Engine".

*******************************************************************************/

class Engine{

	public:
        	void initialize(); //will input and save values of data members
		void start();	//will list all present files and start parsing each one in thread pool.
				//will also check for any new file in sourceFolder folder.
		void showStats();

        	Engine() { }

	~Engine() {
		delete[] sourceFolder;
		delete[] destinationFolder;
	}
	private:
		int getFiles(char dir[], vector<string> &files);
		static void *watchSourceFolder(void *sourceFolder);
		//member functions		

	private: //data members
		char *sourceFolder, *destinationFolder;   // will be given by user.
		pthread_t pthreadid;
		//PCapParser parser;
	
};




#endif
