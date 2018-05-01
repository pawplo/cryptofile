/*
The MIT License (MIT)

Copyright (c) 2018 Pawel Plociennik (github.com/pawplo)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define CBC 1
#include "tiny-AES-c/aes.h"
#include "random.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
void convert_endian(void *buf, int n)
{
	unsigned char c;
	for(int i = 0; i < n/2; i++) {
		c = ((unsigned char *)buf)[i];
		((unsigned char *)buf)[i] = ((unsigned char *)buf)[n-i-1];
		((unsigned char *)buf)[n-i-1] = c;
	}
//	fprintf(stderr, "little endian\n");
}
#else
void convert_endian(void *buf, size_t n)
{
//	fprintf(stderr, "big endian\n");
}
#endif

void usage_and_exit(char *program)
{
	fprintf(stderr, "usage: %s {enc | dec} <key> <in_file> <out_file>\n", program);
	fprintf(stderr, "<key>\t\t256 bit key in 64 bytes hex format.\n\n");
	
	fprintf(stderr, "To generate key you can use hard time and memory key derivation function such as argon2:\n");
	fprintf(stderr, "echo -n \"some-strong-password\" | argon2 some-salt -t 20 -m 20 -r > ./key.txt\n\n");

	fprintf(stderr, "Then encrypt:\n");
	fprintf(stderr, "cryptofile enc `cat ./key.txt` somefile.txt somefile.txt.enc\n\n");

	fprintf(stderr, "And decrypt:\n");
	fprintf(stderr, "cryptofile dec `cat ./key.txt` somefile.txt.enc somefile.txt.enc.dec\n\n");

	fprintf(stderr, "Then somefile.txt and somefile.txt.enc.dec should be the same.\n\n");

	fprintf(stderr, "PS: When you use argon2 to generate key from password remeber to remeber ;)\n");
	fprintf(stderr, "or save not only password but salt and other parameters too.\n\n");

	fprintf(stderr, "github.com/pawplo/cryptofile\n");
	exit(1);
}

void hex_dump(char *prefix, unsigned char *str, int num)
{
	fprintf(stderr, "%s: ", prefix);
	for(int i=0; i<num; i++)
		fprintf(stderr, "%02x", str[i]);
	fprintf(stderr, "\n");
}

#define BUFSIZE 65536

int main(int argc, char *argv[])
{
	static unsigned char buf[BUFSIZE];

	static char *magic_name = "github.com/pawplo/cryptofile\n";
	int magic_name_len = strlen(magic_name);

	static char *mode = "aes-256-cbc----\n";
	int mode_len = 16;

	int ret;
	int size;

	uint64_t file_size = 0;

	int in_file;
	int out_file;

	unsigned char key_bin[33];
	unsigned char iv_bin[17];

	int padding = 0;

	if(argc < 5) {
		usage_and_exit(argv[0]);
	}

	int enc;
	if (strcmp(argv[1], "enc") == 0) {
		enc = 1;
	} else if (strcmp(argv[1], "dec") == 0) {
		enc = 0;
	} else {
		usage_and_exit(argv[0]);
	}

	if (strlen(argv[2]) < 64) {
		fprintf(stderr, "Key must be 64 bytes length !!!\n");
		exit(1);
	}
	int j;
	for(int i=0; i<32; i++) {
		j = i * 2;
		if (argv[2][j] >= '0' && argv[2][j] <= '9')
			key_bin[i] = (argv[2][j] - '0') << 4;
		else if (argv[2][j] >= 'a' && argv[2][j] <= 'f')
			key_bin[i] = (argv[2][j] + 10 - 'a') << 4;
		else if (argv[2][j] >= 'A' && argv[2][j] <= 'F')
			key_bin[i] = (argv[2][j] + 10 - 'A') << 4;
		else {
			fprintf(stderr, "Key char (%c) at position (%d) is invalid !!!\n", argv[2][j], j+1);
			exit(1);
		}
		j++;
		if (argv[2][j] >= '0' && argv[2][j] <= '9')
			key_bin[i] += (argv[2][j] - '0');
		else if (argv[2][j] >= 'a' && argv[2][j] <= 'f')
			key_bin[i] += (argv[2][j] + 10 - 'a');
		else if (argv[2][j] >= 'A' && argv[2][j] <= 'F')
			key_bin[i] += (argv[2][j] + 10 - 'A');
		else {
			fprintf(stderr, "Key char (%c) at position (%d) is invalid !!!\n", argv[2][j], j+1);
			exit(1);
		}
	}
	//hex_dump("key_bin", key_bin, 32);

	in_file = open(argv[3], O_RDONLY);
	if (in_file == -1) {
		fprintf(stderr, "open() [%s]\n", strerror(errno));
		exit(1);
	}

	out_file = open(argv[4], O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if (out_file == -1) {
		fprintf(stderr, "open() [%s]\n", strerror(errno));
		exit(1);
	}

	if (enc) {
		/* magic name */
		ret = write(out_file, magic_name, magic_name_len);
		if (ret != magic_name_len) {
			fprintf(stderr, "magic_name write() [%s]\n", strerror(errno));
			exit(1);
		}

		/* mode */
		ret = write(out_file, mode, mode_len);
		if (ret != mode_len) {
			fprintf(stderr, "mode write() [%s]\n", strerror(errno));
			exit(1);
		}

		/* iv */
		ret = random_bytes(iv_bin, 16);
		if (ret != 0) {
			fprintf(stderr, "random_bytes() (%d)\n", ret);
			exit(1);
		}

		ret = write(out_file, iv_bin, 16);
		if (ret != 16) {
			fprintf(stderr, "iv write() [%s]\n", strerror(errno));
			exit(1);
		}
//		hex_dump("iv_bin", iv_bin, 16);

		/* file size */
		ret = write(out_file, &file_size, 8);
		if (ret != 8) {
			fprintf(stderr, "file_size write() [%s]\n", strerror(errno));
			exit(1);
		}

	} else {
		/* magic name */
		ret = read(in_file, buf, magic_name_len);
		if (ret != magic_name_len) {
			fprintf(stderr, "magic_name read()) [%s]\n", strerror(errno));
			exit(1);
		}
		ret = strncmp((char *)buf, magic_name, magic_name_len);
		if (ret != 0) {
			fprintf(stderr, "cryptofile format name incorect.\n");
			exit(1);
		}

		/* mode */
		ret = read(in_file, buf, mode_len);
		if (ret != mode_len) {
			fprintf(stderr, "mode read()) [%s]\n", strerror(errno));
			exit(1);
		}
		ret = strncmp((char *)buf, mode, mode_len);
		if (ret != 0) {
			fprintf(stderr, "cryptofile format mode incorect.\n");
			exit(1);
		}

		/* iv */
		ret = read(in_file, iv_bin, 16);
		if (ret != 16) {
			fprintf(stderr, "iv read()) [%s]\n", strerror(errno));
			exit(1);
		}
//		hex_dump("iv_bin", iv_bin, 16);

		/* file size */
		ret = read(in_file, &file_size, 8);
		if (ret != 8) {
			fprintf(stderr, "file_size read()) [%s]\n", strerror(errno));
			exit(1);
		}
		convert_endian(&file_size, 8);
	}

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key_bin, iv_bin);

	if (enc) {
		while(1) {
			size = read(in_file, buf, BUFSIZE);
			if (size > 0) {
				if (padding) {
					fprintf(stderr, "error: padding > 0\n");
					exit(1);
				}
				file_size += size;
				if ((size % 16) > 0) {
					ret = random_bytes(&buf[size], 16 - (size % 16));
					if (ret != 0) {
					    fprintf(stderr, "random_bytes() (%d)\n", ret);
					    exit(1);
					}
					padding = 1;
					size = size - (size % 16) + 16;
				}
//				hex_dump("encrypt", buf, size);
				AES_CBC_encrypt_buffer(&ctx, buf, size);
//				hex_dump("encrypt", buf, size);
				if(write(out_file, buf, size) != size) {
					fprintf(stderr, "write [%s]\n", strerror(errno));
					exit(1);
				}

			} else if (size == 0) {
				ret = lseek(out_file, magic_name_len + mode_len + 16, SEEK_SET);
				if (ret != (magic_name_len + mode_len + 16)) {
					fprintf(stderr, "lseek() [%s]\n", strerror(errno));
				}
				convert_endian(&file_size, 8);
				write(out_file, &file_size, 8);

//				fprintf(stderr, "size == 0\n");
				exit(0);
			} else {
//				fprintf(stderr, "size < 0\n");
				exit(0);
			}
		}

	} else {
		uint64_t read_file_size = 0;
		while(1) {
			size = read(in_file, buf, BUFSIZE);
			if (size > 0) {
				if (padding) {
					fprintf(stderr, "file has padding data.\n");
					exit(1);
				}
				read_file_size+=size;
//				hex_dump("decrypt", buf, size);
				AES_CBC_decrypt_buffer(&ctx, buf, size);
//				fprintf(stderr, "file_size == %d,size == %d\n", (int)file_size, size);
//				hex_dump("decrypt", buf, size);
				if (read_file_size >= file_size) {
					size -= (read_file_size - file_size);
					padding = 1;
				}
//				fprintf(stderr, "@size == %d\n", size);
				if(write(out_file, buf, size) != size) {
					fprintf(stderr, "write [%s]\n", strerror(errno));
					exit(1);
				}
			} else if (size == 0) {
//				fprintf(stderr, "dec size == 0\n");
				exit(0);
			} else {
//				fprintf(stderr, "dec size < 0\n");
				exit(0);
			}
		}
	}
	exit(0);
}
