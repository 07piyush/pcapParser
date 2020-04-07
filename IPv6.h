#ifndef IPv6_H
#define IPv6_H


struct IPv6{

	unsigned long long addressFirstHalf,
			   addressSecondHalf;

	bool operator < ( const IPv6 &IPv6Object) {

		bool result = false;
	
		if( this->addressFirstHalf < IPv6Object.addressFirstHalf )
			result = true;

		else if(this->addressFirstHalf < IPv6Object.addressFirstHalf && 
		   this->addressSecondHalf < IPv6Object.addressSecondHalf)
			result = true;

		return result;
	}
	
};


#endif
