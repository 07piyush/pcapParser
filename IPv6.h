#ifndef IPv6_H
#define IPv6_H

#include<cstring>


struct IPv6{
	
	unsigned char address[17];

	bool operator<(const IPv6&) const;
	bool operator==(const IPv6&) const;
	bool operator>(const IPv6&) const;
	

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
	//if (difference < 0) result = true;
}

inline bool IPv6::operator==(const IPv6& rhs) const
{
	bool result = false;

	int difference = strcmp((char*) &address, (char*) &rhs.address);
	if (difference == 0) result = true;

	return result;
}

inline bool IPv6::operator>(const IPv6& rhs) const
{
	bool result = false;

	int difference = strcmp((char*) &address, (char*) &rhs.address);
	if (difference == 0) result = true;

	return result;
}

#endif
