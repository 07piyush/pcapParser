/******************************************************************************
* Funtions definitions in this file:
	* void Engine::initialize()
	* void Engine::start()
	* void *Engine::watchSourceFolder(void *sourceFolder)
	* int Engine::getFiles(vector<string> &files)
	* void Engine::setDestinationFolder(char destinationFolder[])
	

* Global variable: queue<string> remainingFiles.
* Static data member: pthread_mutex_t Engine::mutex. 
	
*******************************************************************************/

#include <iostream>
#include <cstring>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include "includes/Engine.h"
#include <sys/inotify.h>
#include <unistd.h>
#include "includes/pcap/PCapParser.h"
#include <queue>


using namespace std;

#define MAX_PATH_LEN    255
#define NAME_LEN 	32
#define EVENT_SIZE	(sizeof(struct inotify_event))
#define BUF_LEN 	1024 *(EVENT_SIZE + NAME_LEN + 1)
#define MAX_FILE_NAME_LEN 255

extern queue<string> remainingFiles;
pthread_mutex_t Engine::mutex = PTHREAD_MUTEX_INITIALIZER;

void Engine::initialize()
{
	//This funtion simply read source folder and destination folder from user.
	// and set its values to data members.

	char path[MAX_PATH_LEN] = "/home/sharma7/Documents/PcapFiles";
	struct stat statbuf;
	int isDir = 0;
	

	while (true)
	{
		cout << "Enter folder path to process: /home/sharma7/Documents/PcapFiles" << endl;
		//cin>>path;

		if (stat(path, &statbuf) != -1)
		{
			if (S_ISDIR(statbuf.st_mode))
			{
				//sourceFolder = new char[strlen(path) + 1 ];
				strcpy(sourceFolder, path);
				break;
			}
		}
		else
		{
			cout << "Incorrect path!" << endl;
			/*
			   here you might check errno for the reason, ENOENT will mean the path
			   was bad, ENOTDIR means part of the path is not a directory, EACCESS     
			   would mean you can't access the path. Regardless, from the point of 
			   view of your app, the path is not a directory if stat fails. 
			*/
		}
	}

	while (true)
	{
		cout << "Enter folder path to store Statistics: /home/sharma7/Documents/experiment" << endl;
		//cin>>path;
		strcpy(path, "/home/sharma7/Documents/experiment");
		if (stat(path, &statbuf) != -1)
		{
			if (S_ISDIR(statbuf.st_mode))
			{
				//destinationFolder = new char[strlen(path) + 1];
				strcpy(destinationFolder, path);
				break;
			}
		}
		else
		{
			cout << "Incorrect path!" << endl;
		}
	}

	
	//this->start();

}


void Engine::start()
{
	/*This is the actual driver of the whole Engine.
	   Following are the tasks it perform.
		1) Initialize seperate thread for inotify to watch over sourceFolder.
		2) get list of all existing pcap files in the souce folder, store them in vector: files.

	*/
	vector<string> files;
	files.reserve(10);
		
	pthread_create(&pthreadid, NULL, watchSourceFolder, (void *)sourceFolder);

	getFiles(files); //get the existing files in the sourceFolder

	for(string file : files){

		char filePath[MAX_FILE_NAME_LEN];

		strcpy(filePath, sourceFolder);
		strcat(filePath, "/");

		strcat(filePath, file.c_str());
		
		PCapParser parser(destinationFolder);
		
		parser.parse(filePath, file.size());
	}

	while(true) {

		if(!remainingFiles.empty())
		{
			sleep(2);
			PCapParser parser(destinationFolder);
			string targetFile(remainingFiles.front());
			remainingFiles.pop();
			parser.parse((char *)targetFile.c_str(), targetFile.size());
			
		}
	}

}



int Engine::getFiles(vector<string> &files)
{
// This funtion lists all existing pcap files in the souce folder, store them in vector: files.
	
	DIR * dp;
	struct dirent * dirp;
	string directory(sourceFolder);

	if ((dp = opendir(directory.c_str())) == NULL)
	{
		cout << "Error(" << errno << ") opening " << directory << endl;
		return errno;
	}

	while ((dirp = readdir(dp)) != NULL)
	{
		//check if file is .pcap file then add to queue.
		int fileNameLen = strlen(dirp->d_name);
		char *dotPtr = strchr(dirp->d_name, '.');

		if (dotPtr != NULL && strcmp(dotPtr, ".pcap") == 0)
			files.push_back(string(dirp->d_name));
	}

	closedir(dp);
	return 0;
}

void *Engine::watchSourceFolder(void *sourceFolder)
{

/******************************************************************************
* This funtion run on seperate thread and keep a watch on any new pcap file creation.
* as soon as a new file is created, it is parsed and .csv are stored in destination folder.

********************************************************************************/


	cout << "watching folder: " << (char *)sourceFolder << endl;

	int length, i = 0;
	int fd;
	int wd;
	char buffer[BUF_LEN];

	fd = inotify_init();

	if (fd < 0)
	{
		perror("inotify_init");
	}

	wd = inotify_add_watch(fd, (char *)sourceFolder, IN_CREATE );

	while (true)
	{

		i = 0;
		length = read(fd, buffer, BUF_LEN);

		if (length < 0)
		{
			perror("read");
		}

		while (i < length)
		{

			struct inotify_event *event = (struct inotify_event *) &buffer[i];

			if (event->len)
			{

				if (event->mask &IN_CREATE)
				{

					if (event->mask &IN_ISDIR)
					{
						//printf("The directory %s was created.\n", event->name);
					}
					else
					{	
						//File is created check if it is pcap, parse if is true;
						char *dotPtr = strchr(event->name, '.');

						if (dotPtr != NULL && strcmp(dotPtr, ".pcap") == 0)
						{
							pthread_mutex_lock(&mutex);
							char * filePath = new char[strlen((char *)sourceFolder) + (int)strlen(event->name) + 1]; 
							strcpy(filePath, (char *)sourceFolder);
							strcat(filePath, "/");
							strcat(filePath, event->name);
							string filePathCopy(filePath);
							remainingFiles.push(filePathCopy);

							delete[] filePath;
							pthread_mutex_unlock(&mutex);
						}
						
						
					}
				}
				
			}
			i += EVENT_SIZE + event->len;
		}
	}

	(void) inotify_rm_watch(fd, wd);
	(void) close(fd);
	return NULL;

}

void Engine::setDestinationFolder(char destinationFolder[]) { strcpy(this->destinationFolder, destinationFolder); }
