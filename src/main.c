#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "headers/packet_sniffer.h"


void handle_signal(int sig) {
  printf("Interupt signal received, exiting...\n");
  exit(0);
}

int main(int argc, char *argv[]) {
  // Register the SIGINT signal handler to handle Ctrl+C gracefully
  signal(SIGINT, handle_signal);

  // Initialize sniffer config
  const char *net = "eth0";
  if(argc > 1) {
    net = argv[1];
  }
  
  //sniff packets

  // set up any filters

  // Clean up and exit

  return EXIT_SUCCESS;
}