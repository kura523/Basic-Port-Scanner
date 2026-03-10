CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap -lpthread
TARGET = scan

# 列出所有的 .c 文件和对应的 .o 目标文件
SRCS = main.c network.c sender.c sniffer.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

# 链接所有的 .o 文件生成最终的可执行文件
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# 编译每个 .c 文件为 .o 文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理编译产物
clean:
	rm -f $(OBJS) $(TARGET)
