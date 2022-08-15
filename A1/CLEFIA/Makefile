# path macros
BIN_PATH := bin
SRC_PATH := src
DBG_PATH := debug
REF_PATH := ref
INC_PATH := inc

# tool macros
CC := gcc
CCFLAGS := -I$(INC_PATH)
DBGFLAGS := -g

# compile macros
TARGET_NAME := clefia
TARGET := $(BIN_PATH)/$(TARGET_NAME)
TARGET_DEBUG := $(DBG_PATH)/$(TARGET_NAME)

REF_TARGET_NAME := clefia_ref
REF_TARGET := $(BIN_PATH)/$(REF_TARGET_NAME)
REF_TARGET_DEBUG := $(DBG_PATH)/$(REF_TARGET_NAME)

# src files & obj files
SRC := $(SRC_PATH)/clefia.c $(SRC_PATH)/main.c
REF := $(REF_PATH)/clefia_ref.c

# clean files list
CLEAN_LIST := $(TARGET) $(TARGET_DEBUG) $(REF_TARGET) $(REF_TARGET_DEBUG)

# default rule
default: makedir all

# non-phony targets
$(TARGET): $(SRC)
	@echo BUILD $(TARGET)
	$(CC) $(CCFLAGS) -o $@ $(SRC)

$(TARGET_DEBUG): $(SRC)
	@echo BUILD $(TARGET_DEBUG)
	$(CC) $(CCFLAGS) $(DBGFLAGS) -o $@ $(SRC)

$(REF_TARGET): $(REF)
	@echo BUILD $(REF_TARGET)
	$(CC) $(CCFLAGS) -o $@ $(REF)

$(REF_TARGET_DEBUG): $(REF)
	@echo BUILD $(REF_TARGET_DEBUG)
	$(CC) $(CCFLAGS) $(DBGFLAGS) -o $@ $(REF)

all: $(TARGET)

debug: $(TARGET_DEBUG)

reference: $(REF_TARGET) $(REF_TARGET_DEBUG)

# phony rules
.PHONY: makedir
makedir:
	@mkdir -p $(BIN_PATH) $(DBG_PATH) $(REF_PATH) $(INC_PATH)

.PHONY: run
run: $(TARGET)
	$(TARGET)

.PHONY: clean
clean:
	@echo CLEAN $(CLEAN_LIST)
	@rm -f $(CLEAN_LIST)
