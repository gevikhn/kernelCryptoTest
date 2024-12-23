# 编译器设置
CXX = g++
CXXFLAGS = -Wall -O2 -std=c++11

# 目标文件
TARGETS = client proxy

# 源文件和对象文件
CLIENT_SRCS = client.cpp
PROXY_SRCS = proxy.c
CRYPTO_SRC = crypto.cpp

CLIENT_OBJS = $(CLIENT_SRCS:.cpp=.o) crypto.o
PROXY_OBJS = $(PROXY_SRCS:.c=.o) crypto.o

# 头文件依赖
DEPS = crypto.h

# 默认目标
all: $(TARGETS)

# 编译规则
client: $(CLIENT_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

proxy: $(PROXY_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

# 模式规则
%.o: %.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c $(DEPS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

crypto.o: $(CRYPTO_SRC) $(DEPS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# 清理规则
clean:
	rm -f $(TARGETS) *.o

# 防止与同名文件冲突
.PHONY: all clean