#include <stdio.h>
#include <pcap.h>

int main()
{
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "port 80";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr *header;
	const u_char *packet;

	int result = 0;
	int i;
	int enter_cnt;

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return 2;
	}

	printf("Device: %s\n", dev);

	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}

	if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}

	if(pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}

	while((result = pcap_next_ex(handle, &header, &packet)) >= 0)
	{
		if(result == 0) continue;

		if(result == -1) break;

		printf("-------------------------------------------------\n\n");
		printf("Jacked a packet with length of [%d]\n", header->len);
		printf("-------------------------------------------------\n\n");

		printf(" %02x ", packet[0]);
		enter_cnt = 1;

		for(i = 0 ; i < header->len ; ++i)
		{
			printf(" %02x ", packet[i]);
			++enter_cnt;
			
			if(enter_cnt % 15 == 0)
			{
				printf("\n");
			}
		}
		printf("\n-----------------------------------------------\n");
		printf("\n\n\n");
	}
	
	pcap_close(handle);

	printf("Packet Grab End!\n");

	return 0;
}

