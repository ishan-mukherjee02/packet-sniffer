#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include <winsock2.h>         // For Winsock functions

#include "headers/packet_sniffer.h"

// Ethernet header structure
struct ether_header {
    uint8_t ether_dhost[6]; // Destination MAC address
    uint8_t ether_shost[6]; // Source MAC address
    uint16_t ether_type;    // Protocol type (e.g., IPv4, ARP, etc.)
};


void handle_signal(int sig) {
  printf("Interupt signal received, exiting...\n");
  exit(0);
}

void print_menu() {
    printf("Packet Sniffer Options:\n");
    printf("a. List network devices\n");
    printf("b. Start packet capture\n");
    printf("c. Stop packet capture\n");
    printf("d. Exit\n");
}

// Packet handler to process and print captured packets
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("\nPacket captured:\n");

    // Print packet metadata
    printf("  Length: %d bytes\n", header->len);
    printf("  Timestamp: %ld.%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);

    // Decode Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    printf("  Ethernet Header:\n");
    printf("    Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0],
           eth_header->ether_shost[1],
           eth_header->ether_shost[2],
           eth_header->ether_shost[3],
           eth_header->ether_shost[4],
           eth_header->ether_shost[5]);
    printf("    Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0],
           eth_header->ether_dhost[1],
           eth_header->ether_dhost[2],
           eth_header->ether_dhost[3],
           eth_header->ether_dhost[4],
           eth_header->ether_dhost[5]);
    printf("    EtherType: 0x%04x\n", eth_header->ether_type);

    // Decode IP header if the packet is IP
    // if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    //     struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    //     printf("  IP Header:\n");
    //     printf("    Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    //     printf("    Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    //     printf("    Protocol: %d\n", ip_header->ip_p);
    // }
}

int main(int argc, char *argv[]) {
  // Register the SIGINT signal handler to handle Ctrl+C gracefully
  signal(SIGINT, handle_signal);

  // Initialize sniffer config
  const char *net = "\\Device\\NPF_{B7C7BD87-5FF8-429E-92B3-A9DDCA7DCD4E}";
  if(argc > 1) {
    net = argv[1];
  }
  
  char choice;
    while (1) {
        print_menu();
        printf("Enter your choice: ");
        scanf(" %c", &choice);

        switch (choice) {
            case 'a':
                list_network_devices();
                break;
            case 'b':
                if (init_packet_sniffer(net) == 0) {
                    printf("Packet capture started on %s\n", net);
                    start_packet_capture(packet_handler);
                }
                break;
            case 'c':
                stop_packet_sniffer();
                printf("Packet capture stopped.\n");
                break;
            case 'd':
                printf("Exiting...\n");
                exit(EXIT_SUCCESS);
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }

  // sniff packets

  // set up any filters

  // Clean up and exit

  return EXIT_SUCCESS;
}