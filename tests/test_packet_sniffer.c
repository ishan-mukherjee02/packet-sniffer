#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pcap.h>
#include "../src/headers/packet_sniffer.h"

// Mock packet handler for testing
void mock_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Packet captured: length=%d\n", header->len);
}

void test_init_packet_sniffer() {
    printf("Testing init_packet_sniffer...\n");

    // Valid network device (replace "eth0" with your valid device)
    printf("Initializing \\Device\\NPF_{B7C7BD87-5FF8-429E-92B3-A9DDCA7DCD4E}\n");
    assert(init_packet_sniffer("\\Device\\NPF_{B7C7BD87-5FF8-429E-92B3-A9DDCA7DCD4E}") == 0);
    printf("  - Valid device: Passed\n");

    // Invalid network device
    printf("Initializing invalid_device\n");
    assert(init_packet_sniffer("invalid_device") == -1);
    printf("  - Invalid device: Passed\n");

    stop_packet_sniffer(); // Clean up after each test
}

void test_start_packet_capture() {
    printf("Testing start_packet_capture...\n");

    // Valid initialization
    assert(init_packet_sniffer("\\Device\\NPF_{B7C7BD87-5FF8-429E-92B3-A9DDCA7DCD4E}") == 0);

    // Simulate capturing packets (requires actual traffic for meaningful testing)
    printf("  - Starting packet capture (press Ctrl+C to stop)...\n");
    start_packet_capture(mock_packet_handler);

    stop_packet_sniffer(); // Clean up
    printf("  - Capture test: Passed\n");
}

void test_stop_packet_sniffer() {
    printf("Testing stop_packet_sniffer...\n");

    // Valid initialization
    assert(init_packet_sniffer("\\Device\\NPF_{B7C7BD87-5FF8-429E-92B3-A9DDCA7DCD4E}") == 0);

    // Stop the sniffer
    stop_packet_sniffer();
    assert(handle == NULL);
    printf("  - Sniffer stopped successfully: Passed\n");

    // Call stop again to ensure no issues
    stop_packet_sniffer();
    printf("  - Double stop: Passed\n");
}

int main() {
    printf("Running Packet Sniffer Test Suite...\n");

    // list_network_devices();
    // test_init_packet_sniffer();
    // test_start_packet_capture();
    test_stop_packet_sniffer();

    printf("All tests completed.\n");
    return 1;
}
