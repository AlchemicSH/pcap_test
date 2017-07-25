#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

int main(int argc, char *argv[])
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

	if(argc == 1)
	{
		printf("Usage: ./%s [interface_name]\n", argv[0]);
		return -1;
	}

	int result = 0;   // pcap_next_ex function result value
	int i;    // for value
	int enter_cnt;    // count value for print packet

	int tcp_header_length;   // tcp header length value

	int src_port = 0;    // tcp port value (source)
	int dst_port = 0;    // tcp port value (destination)

	dev = argv[1];
	if(dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return 2;
	}

	printf("Device: %s\n", dev);

	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s\n%s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s\n%s\n", dev, errbuf);
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
		src_port = 0;
		dst_port = 0;

		if(result == 0) continue;  // There is no packet.

		if(result == -1) break;    // Signal Lost.

		if(result == -2)      // No moe packets from the packet savefile.
		{
			fprintf(stderr, "No more packets from the packet savefile.\n");
			break;
		}

		// Print packet.
		printf("-----------------------------------------------------------\n");
		printf("Jacked a packet with length of [%d]\n", header->len);
		printf("-----------------------------------------------------------\n");

		enter_cnt = 0;
		for(i = 0 ; i < header->len ; ++i)
		{
			printf(" %02x ", packet[i]);
			++enter_cnt;
			
			if(enter_cnt % 15 == 0)
			{
				printf("\n");
			}
		}
		printf("\n-----------------------------------------------------------\n");

		// Analysis packet information
		// First, Ethernet header information
		/*
		printf("[Ethernet Header]\n");
		printf("Source Mac Address: ");
		printf("%02x", packet[6]);
		for(i = 7 ; i < 12 ; ++i)
		{
			printf(":%02x", packet[i]);
		}
		printf("\n");

		printf("Destination Mac Address: ");
		printf("%02x", packet[0]);
		for(i = 1 ; i < 6 ; ++i)
		{
			printf(":%02x", packet[i]);
		}
		printf("\n\n");
		*/

		struct ether_header *ether = (struct ether_header *)(packet);

		printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", ether->ether_shost[0], ether->ether_shost[1], ether->ether_shost[2], ether->ether_shost[3], ether->ether_shost[4], ether->ether_shost[5]);
		printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", ether->ether_dhost[0], ether->ether_dhost[1], ether->ether_dhost[2], ether->ether_dhost[3], ether->ether_dhost[4], ether->ether_dhost[5]);
		printf("\n");

		// Second, IPv4 header information
		if(packet[sizeof(struct ether_header) - 2] == 0x08 && packet[sizeof(struct ether_header) - 1] == 0x00)
		{
			printf("This packet type is IPv4!\n\n");
			printf("[IPv4 Header]\n");
			/*
			printf("Source IP Address: %d", packet[14 + 12]);
			for(i = 1 ; i < 4 ; ++i)
			{
				printf(".%d", packet[14 + 12 + i]);
			}
			printf("\n");

			printf("Destination IP Address: %d", packet[14 + 16]);
			for(i = 1 ; i < 4 ; ++i)
			{
				printf(".%d", packet[14 + 16 + i]);
			}
			printf("\n\n");
			*/

			struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
			unsigned short ip_header_length = ip_header->ihl * 4;
			struct in_addr src, dst;

			memset(&src, 0, sizeof(src));
			memset(&dst, 0, sizeof(dst));

			src.s_addr = ip_header->saddr;
			dst.s_addr = ip_header->daddr;

			printf("Source IP Address: %s\n", inet_ntoa(src));
			printf("Destination IP Address: %s\n", inet_ntoa(dst));
			printf("\n");

			// Third, TCP header information
			if(packet[sizeof(struct ether_header) + 9] == 0x06)
			{
				printf("This packet protocol is TCP!\n\n");

				tcp_header_length = (int)packet[sizeof(struct ether_header) + sizeof(struct iphdr) + 12] / 4;

				printf("[TCP Header]\n");
				printf("TCP Header Length: %d\n", tcp_header_length);

				struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_length);

				/*
				for(i = (14 + 20) ; i < (14 + 20 + 2) ; ++i)
				{
					if(i == (14 + 20))
					{
						src_port += (int)packet[i] * 16 * 16;
					}
					else
					{
						src_port += (int)packet[i];
					}
				}
				printf("Source Port Number: %d\n", src_port);

				for(i = (14 + 20 + 2) ; i < (14 + 20 + 2 + 2) ; ++i)
				{
					if(i == (14 + 20 + 2))
					{
						dst_port += (int)packet[i] * 16 * 16;
					}
					else
					{
						dst_port += (int)packet[i];
					}
				}
				printf("Destination Port Number: %d\n", dst_port);
				printf("\n");
				*/

				printf("Source Port Number: %u\n", ntohs(tcp_header->source));
				printf("Destination Port Number: %u\n", ntohs(tcp_header->dest));
				printf("\n");

				// Fourth, Data information
				printf("[Data]\n");
				if(packet[sizeof(struct ether_header) + ip_header_length + tcp_header_length] == 0x00)
				{
					printf("There is no data!\n");
				}
				else
				{
					for(i = (14 + 20 + tcp_header_length) ; i < header->len ; ++i)
					{
						printf("%c", packet[i]);
					}
					printf("\n");
				}
			}
			else
			{
				printf("This packet protocol is not TCP!\n");
				continue;
			}
		}
		else
		{
			printf("This packet type is not IPv4!\n");
			continue;
		}

		printf("-----------------------------------------------------------\n");

		printf("\n\n");
	}
	
	pcap_close(handle);

	printf("Packet Grab End!\n");

	return 0;
}

