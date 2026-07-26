# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++11 -Os -s -o Whitebar.exe -mconsole -mwindows -static -lmbedtls -lmbedx509 -lmbedcrypto -lws2_32 -lcomctl32 -lgdi32 -lole32 -lrpcrt4 -lcrypt32 -lbcrypt -mno-mmx -mno-sse -mno-sse2 -lcomdlg32

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
	-lmbedtls -lmbedx509 -lmbedcrypto -lws2_32 -lcomctl32 -lgdi32 -lole32 -lrpcrt4 -lcrypt32 -lbcrypt -lcomdlg32 \
	-mwindows -static -s \
	-o $(TARGET)

# Clean
clean:
	rm -f $(OBJ) $(TARGET) whitebar_linux

# Linux Target
linux:
	$(CXX) Whitebar.cpp -o whitebar_linux `fltk-config --cxxflags` `fltk-config --ldstaticflags` -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -lpthread -ldl -s


