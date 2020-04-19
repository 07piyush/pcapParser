#include <iostream>
#include <cstring>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <chrono>
#include "includes/Engine.h"
#include <sys/inotify.h>
#include <unistd.h>
#include "includes/pcap/PCapParser.h"

using namespace std;

#define MAX_PATH_LEN    255
#define NAME_LEN 	32
#define EVENT_SIZE	(sizeof(struct inotify_event))
#define BUF_LEN 	1024 *(EVENT_SIZE + NAME_LEN + 1)

void Engine::initialize()
{

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
				sourceFolder = new char[strlen(path)];
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
				destinationFolder = new char[strlen(path)];
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

int Engine::getFiles(char dir[], vector<string> &files)
{

	DIR * dp;
	struct dirent * dirp;
	string directory(dir);

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

void Engine::start()
{
	/*This is the actual driver of the whole Engine.
	   Following are the tasks it perform.
		1) Initialize seperate thread for inotify to watch over sourceFolder.
		2)

	*/
	vector<string> files;
	files.reserve(10);
		
	pthread_create(&pthreadid, NULL, watchSourceFolder, (void *)sourceFolder);

	getFiles(sourceFolder, files); //get the existing files in the sourceFolder

	for(string file : files){

		char * filePath = new char[strlen(sourceFolder) + file.size() + 1]; 
		strcpy(filePath, sourceFolder);
		strcat(filePath, "/");
		strcat(filePath, file.c_str());
		PCapParser parser;
		parser.parse(filePath, file.size());
		
		
		delete[] filePath;
	}

	while(true) {  }

}

void *Engine::watchSourceFolder(void *sourceFolder)
{

	cout << "watching folder: " << sourceFolder << endl;
	

	int length, i = 0;
	int fd;
	int wd;
	char buffer[BUF_LEN];

	fd = inotify_init();

	if (fd < 0)
	{
		perror("inotify_init");
	}

	wd = inotify_add_watch(fd, (char *)sourceFolder,
		IN_MODIFY | IN_CREATE | IN_DELETE);

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
					{	cout<< event->name << " added" <<endl;

						//File is created check if it is pcap, parse if is true;
						char *dotPtr = strchr(event->name, '.');

						if (dotPtr != NULL && strcmp(dotPtr, ".pcap") == 0)
						{
							char * filePath = new char[strlen((char *)sourceFolder) + (int)strlen(event->name) + 1]; 
							strcpy(filePath, (char *)sourceFolder);
							strcat(filePath, "/");
							strcat(filePath, event->name);
							PCapParser parser;
							parser.parse(filePath, strlen(filePath));
							//cout << filePath << endl;

							delete[] filePath;
						}
						
						
					}
				}
				else if (event->mask &IN_DELETE)
				{
					if (event->mask &IN_ISDIR)
					{
						//printf("The directory %s was deleted.\n", event->name);
					}
					else
					{
						//printf("The file %s was deleted.\n", event->name);
					}
				}
				else if (event->mask &IN_MODIFY)
				{
					if (event->mask &IN_ISDIR)
					{
						//printf("The directory %s was modified.\n", event->name);
					}
					else
					{
						//printf("The file %s was modified.\n", event->name);
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

void Engine::showStats() {}
