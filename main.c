/*
 * aesc - AES-256-CBC file encryption/decryption tool
 *
 * Maintainer: qjf0 <qianjunfan0@outlook.com>
 *                  <https://github.com/qjf0>
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define VERSION		"alpha 3"
#define SALT_SIZE	32
#define KEY_SIZE	32
#define IV_SIZE		16

/* Error codes */
enum {
	ERR_NONE = 0,
	ERR_OPEN_INPUT,
	ERR_OPEN_OUTPUT,
	ERR_MEMORY,
	ERR_RANDOM,
	ERR_DERIVE_KEY,
	ERR_ENCRYPT_UPDATE,
	ERR_ENCRYPT_FINAL,
	ERR_DECRYPT_UPDATE,
	ERR_DECRYPT_FINAL,
	ERR_WRITE_HEADER,
	ERR_READ_HEADER,
	ERR_INVALID_FILE,
	ERR_WRITE_DATA,
	ERR_FILE_SIZE,
};

/* User configuration */
struct config {
	size_t iterations;
	size_t buffer_size;
	char *input_file;
	char *output_file;
	char *passwd;
	int mode;		/* 0=none, 1=encrypt, 2=decrypt */
	int help;
	int version;
	int quiet;		/* 1 = suppress normal output */
};

static struct config config = {
	.iterations	= 600000,
	.buffer_size	= 64 * 1024,
	.mode		= 0,
	.help		= 0,
	.version	= 0,
	.quiet		= 0,
};

#define MODE_ENCRYPT	1
#define MODE_DECRYPT	2

/* Runtime state */
struct runtime {
	unsigned char salt[SALT_SIZE];
	unsigned char iv[IV_SIZE];
	unsigned char key[KEY_SIZE];
	EVP_CIPHER_CTX *ctx;
	FILE *fin;
	FILE *fout;
	long long total_size;
	long long processed;
	unsigned char *inbuf;
	unsigned char *outbuf;
	size_t buf_size;
};

static struct runtime rt = {0};

/* Function prototypes */
static void parse_arg(int argc, char *argv[]);
static int init(void);
static int derive_key(void);
static int encrypt(void);
static int decrypt(void);
static void quit(void);
static void handle_error(int err) __attribute__((noreturn));
static void usage(void);
static void progress(long long current, long long total);

/* Main */
int main(int argc, char *argv[])
{
	int ret;

	/* Initialize OpenSSL */
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* Parse user options */
	parse_arg(argc, argv);

	/* Handle --help or --version */
	if (config.help) {
		usage();
		quit();
		return 0;
	}
	if (config.version) {
		printf("aesc " VERSION "\n");
		printf("Built with OpenSSL %s\n", OPENSSL_VERSION_TEXT);
		quit();
		return 0;
	}

	/* Validate required arguments */
	if (config.mode == 0) {
		fprintf(stderr, "aesc: missing mode (-e or -d)\n");
		fprintf(stderr, "Try 'aesc --help' for more information.\n");
		quit();
		return 1;
	}
	if (!config.input_file || !config.output_file || !config.passwd) {
		fprintf(stderr, "aesc: missing required options: --if, --of, --pass\n");
		fprintf(stderr, "Try 'aesc --help' for more information.\n");
		quit();
		return 1;
	}

	/* Prepare resources (files, buffers, key, EVP context) */
	ret = init();
	if (ret != ERR_NONE)
		handle_error(ret);

	/* Run encryption or decryption */
	if (config.mode == MODE_ENCRYPT) {
		ret = encrypt();
		if (ret != ERR_NONE)
			handle_error(ret);
		if (!config.quiet)
			printf("\naesc: %s -> %s\n", config.input_file, config.output_file);
	} else {
		ret = decrypt();
		if (ret != ERR_NONE)
			handle_error(ret);
		if (!config.quiet)
			printf("\naesc: %s -> %s\n", config.input_file, config.output_file);
	}

	/* Cleanup */
	quit();
	return 0;
}

/* Parse command line options, all args must be given via options */
static void parse_arg(int argc, char *argv[])
{
	int opt, option_index = 0;
	opterr = 0;

	static struct option long_options[] = {
		{"help",       no_argument,       0, 'h'},
		{"version",    no_argument,       0, 'v'},
		{"encrypt",    no_argument,       0, 'e'},
		{"decrypt",    no_argument,       0, 'd'},
		{"quiet",      no_argument,       0, 'q'},
		{"if",         required_argument, 0, 'i'},
		{"of",         required_argument, 0, 'o'},
		{"bs",         required_argument, 0, 'b'},
		{"iterations", required_argument, 0, 'I'},
		{"pass",       required_argument, 0, 'P'},
		{0, 0, 0, 0}
	};

	/* Iterate through all options */
	while ((opt = getopt_long(argc, argv, "hvedq i:o:b:I:P:",
				  long_options, &option_index)) != -1) {
		switch (opt) {
		case 'h':
			config.help = 1;
			break;
		case 'v':
			config.version = 1;
			break;
		case 'e':
			if (config.mode == MODE_DECRYPT) {
				fprintf(stderr, "Error: cannot specify both -e and -d\n");
				exit(1);
			}
			config.mode = MODE_ENCRYPT;
			break;
		case 'd':
			if (config.mode == MODE_ENCRYPT) {
				fprintf(stderr, "Error: cannot specify both -e and -d\n");
				exit(1);
			}
			config.mode = MODE_DECRYPT;
			break;
		case 'q':
			config.quiet = 1;
			break;
		case 'i':
			config.input_file = optarg;
			break;
		case 'o':
			config.output_file = optarg;
			break;
		case 'b':
			config.buffer_size = (size_t)strtoul(optarg, NULL, 10);
			if (config.buffer_size == 0) {
				fprintf(stderr, "Invalid buffer size: %s\n", optarg);
				exit(1);
			}
			break;
		case 'I':
			config.iterations = (size_t)strtoul(optarg, NULL, 10);
			if (config.iterations < 1000) {
				fprintf(stderr, "Iterations must be at least 1000.\n");
				exit(1);
			}
			break;
		case 'P':
			config.passwd = optarg;
			break;
		case '?':
			/* Handle unknown option or missing argument */
			if (optopt == 'i' || optopt == 'o' || optopt == 'b' ||
			    optopt == 'I' || optopt == 'P')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknown option -%c.\n", optopt);
			fprintf(stderr, "Try 'aesc --help' for more information.\n");
			exit(1);
		default:
			abort();
		}
	}

	/* Reject any positional arguments */
	if (optind < argc) {
		fprintf(stderr, "Extra arguments: ");
		while (optind < argc)
			fprintf(stderr, "%s ", argv[optind++]);
		fprintf(stderr, "\n");
		exit(1);
	}
}

/* Print usage help */
static void usage(void)
{
	printf("Usage: aesc -e|-d --if=FILE --of=FILE --pass=PASSWORD [options]\n");
	printf("Options:\n");
	printf("  -e, --encrypt              Encrypt mode\n");
	printf("  -d, --decrypt              Decrypt mode\n");
	printf("  -h, --help                 Display this help and exit\n");
	printf("  -v, --version              Output version information and exit\n");
	printf("  -q, --quiet                Suppress all normal output (errors still printed)\n");
	printf("  -i, --if=FILE              Input file (required)\n");
	printf("  -o, --of=FILE              Output file (required)\n");
	printf("  -P, --pass=PASSWORD        Password (required)\n");
	printf("  -b, --bs=SIZE              Buffer size (bytes, default 64KB)\n");
	printf("  -I, --iterations=NUM       PBKDF2 iterations (default 600000)\n");
	printf("\n");
	printf("Examples:\n");
	printf("  aesc -e --if input.txt --of output.enc --pass mysecret\n");
	printf("  aesc -d --if output.enc --of decrypted.txt --pass mysecret --quiet\n");
}

/* Print error, clean up and exit. Does not return. */
static void handle_error(int err)
{
	printf("\n");
	/* Print appropriate error message */
	switch (err) {
	case ERR_OPEN_INPUT:
		fprintf(stderr, "aesc: cannot open '%s'\n", config.input_file);
		break;
	case ERR_OPEN_OUTPUT:
		fprintf(stderr, "aesc: cannot create '%s'\n", config.output_file);
		break;
	case ERR_MEMORY:
		fprintf(stderr, "aesc: memory allocation failed\n");
		break;
	case ERR_RANDOM:
		fprintf(stderr, "aesc: failed to generate random salt/IV\n");
		break;
	case ERR_DERIVE_KEY:
		fprintf(stderr, "aesc: key derivation failed\n");
		break;
	case ERR_ENCRYPT_UPDATE:
		fprintf(stderr, "aesc: encryption update failed\n");
		break;
	case ERR_ENCRYPT_FINAL:
		fprintf(stderr, "aesc: encryption finalization failed\n");
		break;
	case ERR_DECRYPT_UPDATE:
		fprintf(stderr, "aesc: decryption update failed\n");
		break;
	case ERR_DECRYPT_FINAL:
		fprintf(stderr, "aesc: wrong password or corrupted file\n");
		break;
	case ERR_WRITE_HEADER:
		fprintf(stderr, "aesc: failed to write salt/IV\n");
		break;
	case ERR_READ_HEADER:
		fprintf(stderr, "aesc: invalid encrypted file (missing header)\n");
		break;
	case ERR_INVALID_FILE:
		fprintf(stderr, "aesc: input file is not encrypted or corrupted\n");
		break;
	case ERR_WRITE_DATA:
		fprintf(stderr, "aesc: failed to write data\n");
		break;
	case ERR_FILE_SIZE:
		fprintf(stderr, "aesc: failed to get file size\n");
		break;
	default:
		fprintf(stderr, "aesc: unknown error\n");
	}
	ERR_print_errors_fp(stderr);
	/* Cleanup and exit */
	quit();
	exit(1);
}

/* Display a simple progress bar on the terminal */
static void progress(long long current, long long total)
{
	int percent, bar_width = 50, pos;

	if (total == 0)
		return;

	percent = (int)((double)current / total * 100);
	pos = (int)((double)current / total * bar_width);

	printf("\r[");
	for (int i = 0; i < bar_width; i++) {
		if (i < pos)
			putchar('=');
		else if (i == pos)
			putchar('>');
		else
			putchar(' ');
	}
	printf("] %3d%%", percent);
	fflush(stdout);
}

/* Derive AES key from password using PBKDF2-HMAC-SHA256 */
static int derive_key(void)
{
	if (!PKCS5_PBKDF2_HMAC(config.passwd, strlen(config.passwd),
			       rt.salt, SALT_SIZE,
			       (int)config.iterations,
			       EVP_sha256(), KEY_SIZE, rt.key))
		return ERR_DERIVE_KEY;
	return ERR_NONE;
}

/* Allocate buffers, open files, read/write header, derive key, init EVP context */
static int init(void)
{
	/* Allocate I/O buffers */
	rt.buf_size = config.buffer_size;
	rt.inbuf = malloc(rt.buf_size);
	rt.outbuf = malloc(rt.buf_size + EVP_MAX_BLOCK_LENGTH);
	if (!rt.inbuf || !rt.outbuf) {
		free(rt.inbuf);
		free(rt.outbuf);
		return ERR_MEMORY;
	}

	/* Open input file and get its size */
	rt.fin = fopen(config.input_file, "rb");
	if (!rt.fin)
		return ERR_OPEN_INPUT;

	if (fseek(rt.fin, 0, SEEK_END) != 0) {
		fclose(rt.fin);
		return ERR_FILE_SIZE;
	}
	rt.total_size = ftell(rt.fin);
	if (rt.total_size < 0) {
		fclose(rt.fin);
		return ERR_FILE_SIZE;
	}
	rewind(rt.fin);

	/* Open output file */
	rt.fout = fopen(config.output_file, "wb");
	if (!rt.fout) {
		fclose(rt.fin);
		return ERR_OPEN_OUTPUT;
	}

	/* Handle header (salt + IV) */
	if (config.mode == MODE_ENCRYPT) {
		/* Generate random salt and IV, write to output */
		if (RAND_bytes(rt.salt, SALT_SIZE) != 1)
			return ERR_RANDOM;
		if (RAND_bytes(rt.iv, IV_SIZE) != 1)
			return ERR_RANDOM;

		if (fwrite(rt.salt, 1, SALT_SIZE, rt.fout) != SALT_SIZE ||
		    fwrite(rt.iv, 1, IV_SIZE, rt.fout) != IV_SIZE)
			return ERR_WRITE_HEADER;
	} else {
		/* Read salt and IV from input */
		if (fread(rt.salt, 1, SALT_SIZE, rt.fin) != SALT_SIZE ||
		    fread(rt.iv, 1, IV_SIZE, rt.fin) != IV_SIZE)
			return ERR_READ_HEADER;

		/* Adjust progress counters (skip header) */
		rt.processed = SALT_SIZE + IV_SIZE;
		rt.total_size -= rt.processed;	/* remaining ciphertext size */
	}

	/* Derive encryption key from password */
	if (derive_key() != ERR_NONE)
		return ERR_DERIVE_KEY;

	/* Create and initialize EVP context */
	rt.ctx = EVP_CIPHER_CTX_new();
	if (!rt.ctx)
		return ERR_MEMORY;

	if (config.mode == MODE_ENCRYPT) {
		if (EVP_EncryptInit_ex(rt.ctx, EVP_aes_256_cbc(), NULL,
				       rt.key, rt.iv) != 1)
			return ERR_ENCRYPT_UPDATE;
	} else {
		if (EVP_DecryptInit_ex(rt.ctx, EVP_aes_256_cbc(), NULL,
				       rt.key, rt.iv) != 1)
			return ERR_DECRYPT_UPDATE;
	}

	return ERR_NONE;
}

/* Encrypt input file and write to output */
static int encrypt(void)
{
	int inlen, outlen;
	rt.processed = 0;

	/* Process file in chunks */
	while ((inlen = fread(rt.inbuf, 1, rt.buf_size, rt.fin)) > 0) {
		/* Encrypt chunk */
		if (EVP_EncryptUpdate(rt.ctx, rt.outbuf, &outlen,
				      rt.inbuf, inlen) != 1)
			return ERR_ENCRYPT_UPDATE;

		/* Write ciphertext chunk */
		if (fwrite(rt.outbuf, 1, outlen, rt.fout) != (size_t)outlen)
			return ERR_WRITE_DATA;

		rt.processed += inlen;
		if (!config.quiet)
			progress(rt.processed, rt.total_size);
	}

	/* Finalize encryption (handle padding) */
	if (EVP_EncryptFinal_ex(rt.ctx, rt.outbuf, &outlen) != 1)
		return ERR_ENCRYPT_FINAL;

	if (fwrite(rt.outbuf, 1, outlen, rt.fout) != (size_t)outlen)
		return ERR_WRITE_DATA;

	return ERR_NONE;
}

/* Decrypt input file and write to output */
static int decrypt(void)
{
	int inlen, outlen;

	/* Process ciphertext in chunks */
	while ((inlen = fread(rt.inbuf, 1, rt.buf_size, rt.fin)) > 0) {
		/* Decrypt chunk */
		if (EVP_DecryptUpdate(rt.ctx, rt.outbuf, &outlen,
				      rt.inbuf, inlen) != 1)
			return ERR_DECRYPT_UPDATE;

		/* Write plaintext chunk */
		if (fwrite(rt.outbuf, 1, outlen, rt.fout) != (size_t)outlen)
			return ERR_WRITE_DATA;

		rt.processed += inlen;
		if (!config.quiet)
			progress(rt.processed - (SALT_SIZE + IV_SIZE),
				 rt.total_size);
	}

	/* Finalize decryption (verify padding) */
	if (EVP_DecryptFinal_ex(rt.ctx, rt.outbuf, &outlen) != 1)
		return ERR_DECRYPT_FINAL;

	if (fwrite(rt.outbuf, 1, outlen, rt.fout) != (size_t)outlen)
		return ERR_WRITE_DATA;

	return ERR_NONE;
}

/* Free resources and clear sensitive data */
static void quit(void)
{
	/* Free EVP context */
	if (rt.ctx) {
		EVP_CIPHER_CTX_free(rt.ctx);
		rt.ctx = NULL;
	}

	/* Close file handles */
	if (rt.fin) {
		fclose(rt.fin);
		rt.fin = NULL;
	}
	if (rt.fout) {
		fclose(rt.fout);
		rt.fout = NULL;
	}

	/* Free buffers */
	if (rt.inbuf) {
		free(rt.inbuf);
		rt.inbuf = NULL;
	}
	if (rt.outbuf) {
		free(rt.outbuf);
		rt.outbuf = NULL;
	}

	/* Wipe sensitive data from memory */
	OPENSSL_cleanse(rt.key, KEY_SIZE);
	OPENSSL_cleanse(rt.salt, SALT_SIZE);
	OPENSSL_cleanse(rt.iv, IV_SIZE);

	/* OpenSSL cleanup */
	EVP_cleanup();
	ERR_free_strings();
}
