# Compiler and flags
CXX = g++
CXXFLAGS = -I/c/Users/Lynden/Downloads/openssl/include -L/c/Users/Lynden/Downloads/openssl -o Whitebar.exe -mconsole -mwindows -static -lssl -lcrypto -lws2_32 -lcomctl32 -lgdi32 -lole32 -lrpcrt4 -lcrypt32 -mno-mmx -mno-sse -mno-sse2 -lcomdlg32

# Resource compiler
RC = windres
RCFLAGS =

# Targets
TARGET = Whitebar.exe
SRC = Whitebar.cpp
RES = app.rc
OBJ = main.o app_res.o

# Default target
all: $(TARGET)

# Compile resource
 app_res.o: app.rc icon.ico
	$(RC) $(RCFLAGS) app.rc $@

# Compile C++ source
main.o: $(SRC)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Link everything
$(TARGET): $(OBJ)
	$(CXX) $(OBJ) \
	-L/c/Users/Lynden/Downloads/openssl \
	-lssl -lcrypto -lws2_32 -lcomctl32 -lgdi32 -lole32 -lrpcrt4 -lcrypt32 -lcomdlg32 \
	-mwindows -static \
	-o $(TARGET)

# Clean
clean:
	rm -f $(OBJ) $(TARGET)
