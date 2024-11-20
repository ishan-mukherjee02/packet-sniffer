#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pcap.h>
#include "../src/headers/packet_sniffer.h"

// Mock interface for testing (change based on your environment)
#define TEST_INTERFACE "lo" // Use "lo" for loopback on Linux or adjust for your system.

void test_initialize_packet_sniffer_valid_interface() {
    pcap_t *handle = initialize_packet_sniffer(TEST_INTERFACE);
    assert(handle != NULL);
    printf("test_initialize_packet_sniffer_valid_interface passed!\n");
    pcap_close(handle);
}

void test_initialize_packet_sniffer_invalid_interface() {
    pcap_t *handle = initialize_packet_sniffer("invalid_interface");
    assert(handle == NULL);
    printf("test_initialize_packet_sniffer_invalid_interface passed!\n");
}

void test_set_packet_filter_valid() {
    pcap_t *handle = initialize_packet_sniffer(TEST_INTERFACE);
    assert(handle != NULL);

    int result = set_packet_filter(handle, "tcp");
    assert(result == 0);
    printf("test_set_packet_filter_valid passed!\n");
    pcap_close(handle);
}

void test_set_packet_filter_invalid() {
    pcap_t *handle = initialize_packet_sniffer(TEST_INTERFACE);
    assert(handle != NULL);

    int result = set_packet_filter(handle, "invalid_filter");
    assert(result == -1);
    printf("test_set_packet_filter_invalid passed!\n");
    pcap_close(handle);
}

void test_cleanup_packet_sniffer() {
    pcap_t *handle = initialize_packet_sniffer(TEST_INTERFACE);
    assert(handle != NULL);

    cleanup_packet_sniffer(handle);
    printf("test_cleanup_packet_sniffer passed!\n");
}

int main() {
    printf("Running tests...\n");

    test_initialize_packet_sniffer_valid_interface();
    test_initialize_packet_sniffer_invalid_interface();
    test_set_packet_filter_valid();
    test_set_packet_filter_invalid();
    test_cleanup_packet_sniffer();

    printf("All tests passed!\n");
    return 0;
}
