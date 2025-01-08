#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>

/**
 * Setups the packet sniffer on a given network interface
 * 
 * @param interface The name of the network interface to listen on
 * @return 0 on success, 1 on failure
 */
int init_packet_sniffer(const char  *net);

/**
 * Lists all available network devices
 */
void list_network_devices();

/**
 * Starts the packet capture process
 * 
 * @param packet_handler Callback function to process each captured packet.
 *                       Should match the function signature of pcap_handler.
 */
void start_packet_capture(void (*packet_handler)(u_char *args, const struct pcap_pkthdr *header, const u_char *packet));

/**
 * Stops the packet sniffer and cleans up resources.
 */
void stop_packet_sniffer(void);

// Global Variables

/**
 * Pointer to the pcap handle for the current capture session.
 * This is initialized in init_packet_sniffer and used throughout the program.
 */
extern pcap_t *handle;


#endif // PACKET_SNIFFER_H