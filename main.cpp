#include <iostream>
#include <fstream>
#include "includes/Engine.h"

using namespace std;


int main()
{
	Engine eng;
	eng.initialize(); //ask for source folder, destination folder;
	eng.start();
	//eng.showStats();


    return 0;
}
