#include "headers/packet_sniffer.h"
#include <stdio.h>

pcap_t *handle = NULL;

int init_packet_sniffer(const char *net) {
    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer to hold error messages

    handle = pcap_open_live(net, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", net, errbuf);
        return -1;
    }
    return 0;
}

void start_packet_capture(void (*packet_handler)(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)) {
    pcap_loop(handle, 0, packet_handler, NULL);
}

void stop_packet_sniffer(void) {
    pcap_close(handle);
    handle = NULL;
}
