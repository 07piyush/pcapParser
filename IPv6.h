/**********************************************************************************

* This file is part of c++ assignment 2 and assignment 3.
* This file is declaration of structure "IPv6".
* This structure is used to store 128 bit address, also to represent it in appropriate format.
* Objective of this structure is to provide abstract form to work with ipv6 address.
* also to derived information so as to write into a .csv file.

*******************************************************************************/


#ifndef IPv6_H
#define IPv6_H

#include <cstring>
#include <string>
using namespace std;


struct IPv6{
	
	unsigned char address[17];	// contains exaclty 128 bit of binary of the address.

	bool operator < (const IPv6&) const;
	
	//This funtion returns and save address in format into result, array provided.
	unsigned char *getaddressFormated(unsigned char result[]){
		
		int index = 0;
		unsigned char ch1, ch2;
		for(int byte = 0; byte < 14; byte+=2){
			unsigned char ch1, ch2;
			ch1 = address[byte]; ch2 = address[byte+1];
			index += snprintf((char *)result+index, 4, "%x", ch1);
			index += snprintf((char *)result+index, 4, "%x:", ch2);
		}
		ch1 = address[14]; ch2 = address[15];
		index += snprintf((char *)result+index, 4, "%x", ch1);
		index += snprintf((char *)result+index, 4, "%x", ch2);
		

	return result;
	}
	
};

inline bool IPv6::operator<(const IPv6& rhs) const
{
	return ( strcmp((char*) &this->address, (char*) &rhs.address) < 0 );
}




struct IPv6Hasher
{
  size_t
  operator()(const IPv6 & obj) const
  {
    string targetString = (char *)obj.address;
    return std::hash<std::string>()( targetString );
  }
};


struct IPv6Comparator
{
  bool
  operator()(const IPv6 & obj1, const IPv6 & obj2) const
  {
    if ( strcmp((char*) &obj1.address, (char*) &obj2.address) == 0 )
      return true;
    return false;
  }

};


#endif
