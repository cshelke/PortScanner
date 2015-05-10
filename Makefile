default: portScanner_multi portscanner_single

portScanner_multi:
	g++ portScanner_multi.cpp -o ps_multi -lpthread
	
portscanner_single:
	g++ portscanner_single.cpp -o ps_single -lpthread

clean:
	rm ps_multi ps_single
