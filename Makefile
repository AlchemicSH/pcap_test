packet_test: pcap_test.c
	gcc -o pcap_test pcap_test.c -l pcap

clean:
	rm pcap_test

