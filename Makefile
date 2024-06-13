# Define compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Ishared_resources/include 
LDFLAGS = -Lshared_resources/lib -lshared_resources

# Directories
SRC_DIRS = client proxy server shared_resources/src
BUILD_DIR = build
LIB_DIR = shared_resources/lib
INCLUDE_DIR = shared_resources/include

# Source files
CLIENT_SRC = $(wildcard client/*.cpp)
PROXY_SRC = $(wildcard proxy/*.cpp)
SERVER_SRC = $(wildcard server/*.cpp)
SHARED_SRC = $(wildcard shared_resources/src/*.cpp)

# Object files
CLIENT_OBJ = $(CLIENT_SRC:%.cpp=$(BUILD_DIR)/%.o)
PROXY_OBJ = $(PROXY_SRC:%.cpp=$(BUILD_DIR)/%.o)
SERVER_OBJ = $(SERVER_SRC:%.cpp=$(BUILD_DIR)/%.o)
SHARED_OBJ = $(SHARED_SRC:%.cpp=$(BUILD_DIR)/%.o)

# Targets
TARGETS = client_exec proxy_exec server_exec

# Default target
all: $(LIB_DIR)/libshared_resources.a $(TARGETS)

# Build shared resources static library
$(LIB_DIR)/libshared_resources.a: $(SHARED_OBJ)
	@mkdir -p $(@D)
	ar rcs $@ $^

# Build client executable
client_exec: $(CLIENT_OBJ) $(LIB_DIR)/libshared_resources.a
	$(CXX) $(CLIENT_OBJ) $(LDFLAGS) -o $@

# Build server executable
server_exec: $(SERVER_OBJ) $(LIB_DIR)/libshared_resources.a
	$(CXX) $(SERVER_OBJ) $(LDFLAGS) -o $@

# Build proxy executable
# Build proxy executable
proxy_exec: $(PROXY_OBJ) $(filter-out build/client/main.o, $(CLIENT_OBJ)) $(filter-out build/server/main.o, $(SERVER_OBJ)) $(LIB_DIR)/libshared_resources.a
	$(CXX) $(PROXY_OBJ) $(filter-out build/client/main.o, $(CLIENT_OBJ)) $(filter-out build/server/main.o, $(SERVER_OBJ)) $(LDFLAGS) -o $@
$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up build directories
clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR) $(TARGETS)

.PHONY: all clean

