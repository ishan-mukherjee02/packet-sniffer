# Paths (update with the actual Npcap SDK paths)
INCLUDE_PATH = npcap\Include
LIBRARY_PATH = npcap\Lib

# Compiler and Linker Flags
CFLAGS = -I$(INCLUDE_PATH)
LDFLAGS = -L$(LIBRARY_PATH) -lwpcap -lPacket

# Build target
packet_sniffer: main.c packet_sniffer.c
    gcc -o packet_sniffer main.c packet_sniffer.c $(CFLAGS) $(LDFLAGS)

test: $(TEST_SRC)
	$(CC) $(CFLAGS) $(TEST_SRC) -o test_runner $(CFLAGS) $(LDFLAGS)
	./test_runner