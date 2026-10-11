CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE -Iinclude
LDFLAGS = -lpcap -lcurl -lpthread -lm

SRC = src/json.c src/util.c src/event_logger.c src/signature_detector.c \
      src/anomaly_detector.c src/alert_sender.c src/packet_processor.c src/main.c
OBJ = $(SRC:.c=.o)
BIN = ids

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $(BIN) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean
