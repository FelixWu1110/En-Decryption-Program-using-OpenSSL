ufsend:ufsend.cpp ufrec.cpp
	g++ -o ufsend ufsend.cpp -lssl -lcrypto
	g++ -o ufrec ufrec.cpp -lssl -lcrypto
