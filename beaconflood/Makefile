# Makefile for beaconflood.c

# 컴파일러 설정
CC = gcc
CFLAGS = -g -Wall -Wextra -pedantic -std=c99
LDFLAGS = -lpcap

# 대상 파일 이름
TARGET = beaconflood

# 소스 파일
SRC = beaconflood.c

# 객체 파일 (자동으로 생성)
OBJ = $(SRC:.c=.o)

# 기본 타겟
all: $(TARGET)

# 타겟 빌드
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 개별 객체 파일 빌드
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 정리
clean:
	rm -f $(OBJ) $(TARGET)

# 테스트 실행
run: $(TARGET)
	sudo ./$(TARGET) <monitor_interface> ssid-list.txt

