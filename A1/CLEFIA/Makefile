# path macros
BIN_PATH := bin
OBJ_PATH := obj
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

# src files & obj files
SRC := $(foreach x, $(SRC_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ := $(addprefix $(OBJ_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC)))))
OBJ_DEBUG := $(addprefix $(DBG_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC)))))

# clean files list
DISTCLEAN_LIST := $(OBJ) $(OBJ_DEBUG)
CLEAN_LIST := $(TARGET) $(TARGET_DEBUG)	$(DISTCLEAN_LIST)

# default rule
default: makedir all

# non-phony targets
$(TARGET): $(SRC)
	@echo BUILD $(TARGET)
	$(CC) $(CCFLAGS) -o $@ $(SRC)

$(TARGET_DEBUG): $(SRC)
	@echo BUILD $(TARGET_DEBUG)
	$(CC) $(CCFLAGS) $(DBGFLAGS) -o $@ $(SRC)

all: $(TARGET)

debug: $(TARGET_DEBUG)

# phony rules
.PHONY: makedir
makedir:
	@mkdir -p $(BIN_PATH) $(OBJ_PATH) $(DBG_PATH) $(REF_PATH) $(INC_PATH)

.PHONY: run
run: $(TARGET)
	$(TARGET)

.PHONY: clean
clean:
	@echo CLEAN $(CLEAN_LIST)
	@rm -f $(CLEAN_LIST)

.PHONY: distclean
distclean:
	@echo CLEAN $(DISTCLEAN_LIST)
	@rm -f $(DISTCLEAN_LIST)
