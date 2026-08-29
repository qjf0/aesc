#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define VERSION     "alpha 1"
#define SALT_SIZE   8
#define KEY_SIZE    32
#define IV_SIZE     16
#define ITERATIONS  600000 
#define BUFFER_SIZE (64 * 1024)

void encrypt(const char *input_file, const char *output_file, const char *passwd);
void decrypt(const char *input_file, const char *output_file, const char *passwd);
void usage(void);
void handle_errors(void);
void derive_key(const char *passwd, const unsigned char *salt, unsigned char *key);
void progress(long long current, long long total);

int main(int argc, char *argv[])
{
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        if (argc < 2) {
                usage();
                return 1;
        }

        char *command = argv[1];

        if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0) {
                usage();
                return 0;
        }

        if (strcmp(command, "-v") == 0 || strcmp(command, "--version") == 0) {
                printf("aesc "VERSION"\n");
                printf("Built with OpenSSL %s\n", OPENSSL_VERSION_TEXT);
                return 0;
        }

        if (argc != 5) {
                usage();
                return 1;
        }

        char *input_file = argv[2];
        char *output_file = argv[3];
        char *passwd = argv[4];

        if (strcmp(command, "-e") == 0) {
                encrypt(input_file, output_file, passwd);
                printf("\naesc: %s -> %s\n", input_file, output_file);
        } else if (strcmp(command, "-d") == 0) {
                decrypt(input_file, output_file, passwd);
                printf("\naesc: %s -> %s\n", input_file, output_file);
        } else {
                fprintf(stderr, "aesc: unknown option '%s'\n", command);
                fprintf(stderr, "Try 'aesc --help' for more information.\n");
                return 1;
        }

        EVP_cleanup();
        ERR_free_strings();

        return 0;
}

void usage(void)
{
        printf("Usage: aesc [options] <input> <output> <password>\n");
        printf("\n");
        printf("Options:\n");
        printf("  -e                     Encrypt mode\n");
        printf("  -d                     Decrypt mode\n");
        printf("  -h, --help             Display this help and exit\n");
        printf("  -v, --version          Output version information and exit\n");
        printf("\n");
        printf("Examples:\n");
        printf("  aesc -e input.c output.c your_password\n");
        printf("  aesc -d input.c output.c your_password\n");
}

void handle_errors(void)
{
        ERR_print_errors_fp(stderr);
        abort();
}

void derive_key(const char *passwd, const unsigned char *salt, unsigned char *key)
{
        if (!PKCS5_PBKDF2_HMAC(passwd, strlen(passwd), salt, SALT_SIZE,
                              ITERATIONS, EVP_sha256(), KEY_SIZE, key)) {
                fprintf(stderr, "aesc: key derivation failed\n");
                handle_errors();
        }
}

void progress(long long current, long long total)
{
        int percent = (int)((double)current / total * 100);
        int bar_width = 50;
        int pos = (int)((double)current / total * bar_width);

        printf("\r[");
        for (int i = 0; i < bar_width; i++) {
                if (i < pos) {
                        printf("=");
                } else if (i == pos) {
                        printf(">");
                } else {
                        printf(" ");
                }
        }
        printf("] %3d%%", percent);
        fflush(stdout);
}

void encrypt(const char *input_file, const char *output_file, const char *passwd)
{
        FILE *fin, *fout;
        unsigned char salt[SALT_SIZE];
        unsigned char iv[IV_SIZE];
        unsigned char key[KEY_SIZE];
        long long total_size = 0;
        long long processed = 0;

        fin = fopen(input_file, "rb");
        if (!fin) {
                fprintf(stderr, "aesc: cannot open '%s'\n", input_file);
                exit(1);
        }

        fseek(fin, 0, SEEK_END);
        total_size = ftell(fin);
        fseek(fin, 0, SEEK_SET);

        fout = fopen(output_file, "wb");
        if (!fout) {
                fprintf(stderr, "aesc: cannot create '%s'\n", output_file);
                fclose(fin);
                exit(1);
        }

        if (RAND_bytes(salt, SALT_SIZE) != 1) {
                fprintf(stderr, "aesc: failed to generate salt\n");
                handle_errors();
        }

        if (RAND_bytes(iv, IV_SIZE) != 1) {
                fprintf(stderr, "aesc: failed to generate IV\n");
                handle_errors();
        }

        derive_key(passwd, salt, key);

        if (fwrite(salt, 1, SALT_SIZE, fout) != SALT_SIZE) {
                fprintf(stderr, "aesc: failed to write salt\n");
                fclose(fin);
                fclose(fout);
                exit(1);
        }
        if (fwrite(iv, 1, IV_SIZE, fout) != IV_SIZE) {
                fprintf(stderr, "aesc: failed to write IV\n");
                fclose(fin);
                fclose(fout);
                exit(1);
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
                fprintf(stderr, "aesc: failed to create encryption context\n");
                handle_errors();
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
                fprintf(stderr, "aesc: failed to initialize encryption\n");
                handle_errors();
        }

        unsigned char inbuf[BUFFER_SIZE];
        unsigned char outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
        int inlen, outlen;

        while ((inlen = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
                if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
                        fprintf(stderr, "aesc: encryption failed\n");
                        handle_errors();
                }
                if (fwrite(outbuf, 1, outlen, fout) != (size_t)outlen) {
                        fprintf(stderr, "aesc: failed to write encrypted data\n");
                        handle_errors();
                }

                processed += inlen;
                progress(processed, total_size);
        }

        if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
                fprintf(stderr, "aesc: failed to finalize encryption\n");
                handle_errors();
        }
        if (fwrite(outbuf, 1, outlen, fout) != (size_t)outlen) {
                fprintf(stderr, "aesc: failed to write final encrypted data\n");
                handle_errors();
        }

        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
}

void decrypt(const char *input_file, const char *output_file, const char *passwd)
{
        FILE *fin, *fout;
        unsigned char salt[SALT_SIZE];
        unsigned char iv[IV_SIZE];
        unsigned char key[KEY_SIZE];
        long long total_size = 0;
        long long processed = 0;

        fin = fopen(input_file, "rb");
        if (!fin) {
                fprintf(stderr, "aesc: cannot open '%s'\n", input_file);
                exit(1);
        }

        fseek(fin, 0, SEEK_END);
        total_size = ftell(fin);
        fseek(fin, 0, SEEK_SET);

        if (fread(salt, 1, SALT_SIZE, fin) != SALT_SIZE) {
                fprintf(stderr, "aesc: invalid encrypted file (missing salt)\n");
                fclose(fin);
                exit(1);
        }

        if (fread(iv, 1, IV_SIZE, fin) != IV_SIZE) {
                fprintf(stderr, "aesc: invalid encrypted file (missing IV)\n");
                fclose(fin);
                exit(1);
        }

        derive_key(passwd, salt, key);

        fout = fopen(output_file, "wb");
        if (!fout) {
                fprintf(stderr, "aesc: cannot create '%s'\n", output_file);
                fclose(fin);
                exit(1);
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
                fprintf(stderr, "aesc: failed to create decryption context\n");
                handle_errors();
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
                fprintf(stderr, "aesc: failed to initialize decryption\n");
                handle_errors();
        }

        unsigned char inbuf[BUFFER_SIZE];
        unsigned char outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
        int inlen, outlen;

        const long long header_size = SALT_SIZE + IV_SIZE;
        processed = header_size;

        while ((inlen = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
                if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
                        fprintf(stderr, "aesc: decryption failed\n");
                        handle_errors();
                }
                if (fwrite(outbuf, 1, outlen, fout) != (size_t)outlen) {
                        fprintf(stderr, "aesc: failed to write decrypted data\n");
                        handle_errors();
                }

                processed += inlen;
                progress(processed, total_size);
        }

        if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
                fprintf(stderr, "aesc: wrong password or corrupted file\n");
                fclose(fin);
                fclose(fout);
                remove(output_file);
                exit(1);
        }

        if (fwrite(outbuf, 1, outlen, fout) != (size_t)outlen) {
                fprintf(stderr, "aesc: failed to write final decrypted data\n");
                handle_errors();
        }

        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
}
