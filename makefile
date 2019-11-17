# main make file
#VPATH=src


CC=gcc
CFLAGS=-c -Wall -fPIC 
LDFLAGS=
SOURCES= src/app_tsshark/app_tsshark.c src/common/ts_parser.c  src/common/output.c src/common/si_parser.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=tsshark

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.PHONY: clean
clean: 
	rm -f src/app_tsshark/*.o 
	rm -f src/common/*.o 
	rm -f tsshark


	


