// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

// Include libraries
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "conio.h"
#include "pcap.h"
#include "protocol_headers.h"


// Function declarations
pcap_if_t* select_device(pcap_if_t* devices);
void print_raw_data(unsigned char* data, int data_length);

char* encrypt_data(char* message, char* key) {
	// Vigenere algorithm
	size_t messageLen = strlen(message);
	size_t keyLen = strlen(key);

	if (messageLen == 0 || keyLen == 0) {
		return NULL;
	}

	for (size_t i = 0; i < messageLen; ++i) {
		if (message[i] >= 'A' && message[i] <= 'Z') {
			message[i] = 'A' + (message[i] - 'A' + key[i % keyLen] - 'A') % 26;
		}
		else if (message[i] >= 'a' && message[i] <= 'z') {
			message[i] = 'a' + (message[i] - 'a' + key[i % keyLen] - 'a') % 26;
		}
	}

	return message;
}


// Print packet headers
void print_winpcap_header(const struct pcap_pkthdr* packet_header, int packet_counter);
void print_ethernet_header(ethernet_header* eh);
void print_ip_header(ip_header* ih);
void print_icmp_header(icmp_header* icmph);
void print_udp_header(udp_header* uh);
void print_application_data(unsigned char* data, long data_length);
int j = 0;
int k=0;
char key[] = "FAKS";
char copy[10000];
void packet_handler(unsigned char* fd, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data) {
	memset(copy, 0, sizeof(copy));
	time_t timestamp; // Raw time (bits) when packet is received
	struct tm* local_time; // Local time when packet is received
	char time_string[16]; // Local time converted to string
	j += 1;
	// Convert the timestamp to readable format
	timestamp = packet_header->ts.tv_sec;
	local_time = localtime(&timestamp);
	strftime(time_string, sizeof time_string, "%H:%M:%S", local_time);
	printf("\n%d.Paket,%s", j, time_string);


	ethernet_header* eh = (ethernet_header*)packet_data;
	ip_header* ih = (ip_header*)(packet_data + sizeof(ethernet_header));
	int length_bytes = ih->header_length * 4;
	if (ntohs(eh->type) == 0x0800) {

		printf("\nAdresa posiljaoca:%d.%d.%d.%d\n", ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);
		printf("\nTime to live:%d", ih->ttl);

		if (ih->next_protocol == 1) {
			printf("\nICMP Protokol\n");
			icmp_header* icmp = (icmp_header*)(packet_data + sizeof(ethernet_header));
			printf("SADRZAJ:");
			for (int i = 0; i < 4; i++) {
				printf("%c", icmp->data[i]);
			}
			printf("TIP:%d", icmp->type);
		}
		else if (ih->next_protocol == 0x6) {
			printf("\nTCP protokol");

			tcp_header* th = (tcp_header*)((unsigned char*)ih + length_bytes);
			if (th->ack_num != 0) {
				printf("\nSRC Port:%u\n", ntohs(th->src_port));
				printf("\nDEST Port:%u\n", ntohs(th->dest_port));
				printf("\nACK BIT:%d\n", th->ack_num);
			}
			unsigned char* app_data = (unsigned char*)th + (th->header_length * 4);
			if (ntohs(th->src_port) == 80 || ntohs(th->dest_port) == 80) {
				k += 1;
				printf("\nDATA:%c\n", app_data[1]);
				printf("Broj http paketa:%d", k);
			}
			double percentage = k;
			printf("\nUKUPAN Udeo HTTP protokola je:%f", percentage / j);

		}
		else if (ih->next_protocol == 0x11) {
			printf("\n\nUDP protocol\n");

			udp_header* uh = (udp_header*)((unsigned char*)ih + length_bytes);
			printf("SRC-PORT:%u\n", ntohs(uh->src_port));
			printf("DEST-PORT:%u\n", ntohs(uh->dest_port));
			unsigned char* app_data = (unsigned char*)uh + sizeof(udp_header);
			int data_len = ntohs(uh->datagram_length) - sizeof(udp_header);
			printf("DATAGRAM-LEN:%d", uh->datagram_length);
			printf("CHECKSUM:%d", uh->checksum);
			char* coded = encrypt_data((char*)app_data, key);
			memcpy(copy + sizeof(ethernet_header) + ih->header_length * 4 + sizeof(udp_header), coded, strlen(coded));
			pcap_dump((unsigned char*)fd, packet_header, (const unsigned char*)copy);
			printf("--------DATA--------------\n");
			for (int i = 0; i < 16; i++) {
				printf("%c", app_data[i]);
			}
		}

	}
}
	
	
	

void handler2(unsigned char* fd, const struct pcap_pkthdr*
	packet_header, const unsigned char* packet_data) {
	pcap_dump(fd, packet_header, packet_data);
}

int main()
{
	pcap_if_t* devices;
	pcap_if_t* device;
	pcap_t* device_handle;
	int i = 0;
	
	char errMessage[PCAP_ERRBUF_SIZE];
	int br;
	

	
	if ((device_handle = pcap_open_offline("packetsv12.pcap",errMessage ))==NULL) {
		printf("\nError opening file...");
		
		return -1;

    }
	if (pcap_datalink(device_handle) != DLT_EN10MB) {
		printf("Error,this program only works on ethernet networks...");
		return -1;
	}
	char filter_exp[] = "ip and (udp or tcp)";
	struct bpf_program fcode;

	if (pcap_compile(device_handle, &fcode, filter_exp, 1, 0xffffff) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}
	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}
	pcap_dumper_t* file_dumper = pcap_dump_open(device_handle, "encrypted_packets.pcap");
	if (file_dumper == NULL)
	{
		printf("\n Error opening output file\n");
		return -1;
	}
	
	


	pcap_loop(device_handle, 10, packet_handler, (unsigned char *)file_dumper);
	pcap_close(device_handle);
	
	return 0;
}

