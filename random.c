#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int random_bytes(unsigned char *buf, int num)
{
	static int in_file = -1;
	int ret;
	
	if (in_file == -1) {
		in_file = open("/dev/random", O_RDONLY);
		if (in_file == -1) {
			fprintf(stderr, "open() [%s]\n", strerror(errno));
			return 1;
		}
	}
	ret = read(in_file, buf, num);
	if (ret != num)
		return 1;
	return 0;
}