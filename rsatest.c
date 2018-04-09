#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

static int rsa_public_encrypt(char *pubkeyfile, int len, char *src, char *dst)
{
    RSA  *rsa = NULL;
    FILE *fp  = NULL;
    int   ret;

    fp = fopen(pubkeyfile, "rb");
    if (!fp) {
        printf("failed to open public key file: %s !\n", pubkeyfile);
        return -1;
    } else {
//      rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
        rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
        fclose(fp);
    }

    if (!rsa) {
        printf("failed to read public key !\n");
        return -1;
    }

    ret = RSA_public_encrypt(len, src, dst, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return ret;
}

static int rsa_private_decrypt(char *privkeyfile, int len, char *src, char *dst)
{
    RSA  *rsa = NULL;
    FILE *fp  = NULL;
    int   ret;

    fp = fopen(privkeyfile, "rb");
    if (!fp) {
        printf("failed to open private key file: %s !\n", privkeyfile);
        return -1;
    } else {
        rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
    }

    if (!rsa) {
        printf("failed to read private key !\n");
        return -1;
    }

    ret = RSA_private_decrypt(len, src, dst, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return ret;
}

static int rsa_private_encrypt(char *privkeyfile, int len, char *src, char *dst)
{
    RSA  *rsa = NULL;
    FILE *fp  = NULL;
    int   ret;

    fp = fopen(privkeyfile, "rb");
    if (!fp) {
        printf("failed to open public key file: %s !\n", privkeyfile);
        return -1;
    } else {
        rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
    }

    if (!rsa) {
        printf("failed to read public key !\n");
        return -1;
    }

    ret = RSA_private_encrypt(len, src, dst, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return ret;
}

static int rsa_public_decrypt(char *pubkeyfile, int len, char *src, char *dst)
{
    RSA  *rsa = NULL;
    FILE *fp  = NULL;
    int   ret;

    fp = fopen(pubkeyfile, "rb");
    if (!fp) {
        printf("failed to open private key file: %s !\n", pubkeyfile);
        return -1;
    } else {
//      rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
        rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
        fclose(fp);
    }

    if (!rsa) {
        printf("failed to read private key !\n");
        return -1;
    }

    ret = RSA_public_decrypt(len, src, dst, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return ret;
}

static void md5_bin_to_str(uint8_t md5[16], char *str)
{
    sprintf(str, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            md5[0],md5[1],md5[2 ],md5[3 ],md5[4 ],md5[5 ],md5[6 ],md5[7 ],
            md5[8],md5[9],md5[10],md5[11],md5[12],md5[13],md5[14],md5[15]);
}

static void md5_str_to_bin(char *str, uint8_t md5[16])
{
    char buf[33];
    int  i, a, b;
    strcpy(buf, str);
    strupr(buf);
    for (i=0; i<16; i++) {
        a = buf[i*2 + 0] - '0';
        b = buf[i*2 + 1] - '0';
        if (a > 9) a -= 7;
        if (b > 9) b -= 7;
        md5[i] = (a << 4) | (b << 0);
    }
}

int main(int argc, char *argv[])
{
    char *filename = NULL;
    FILE *fp       = NULL;
    uint8_t signature[256]= {};
    uint8_t txt_md5  [16 ]= {};
    uint8_t sig_md5  [16 ]= {};
    char    temp     [256]= {};
    MD5_CTX md5ctx        = {};
    int     len, i;

    filename = argc < 2 ? "report.txt" : argv[1];
    fp = fopen(filename, "rb");
    if (!fp) {
        printf("failed to open input file: %s\n", filename);
        return 0;
    }

    // read signature
    for (i=0; i<16; i++) {
        fscanf(fp, "%s", temp);
        md5_str_to_bin(temp, signature + 16 * i);
    }

    fgets(temp, 256, fp);
    MD5_Init(&md5ctx);
    while (!feof(fp)) {
        len = fread(temp, 1, 256, fp);
        if (len <= 0 || len > 256) {
            break;
        }
        MD5_Update(&md5ctx, temp, len);
    }
    MD5_Final(txt_md5, &md5ctx);
    fclose(fp);

    md5_bin_to_str(txt_md5, temp);
    printf("txt_md5: %s\n", temp);

#if 0
    rsa_private_encrypt("private.key", 16, txt_md5, signature);
    for (i=0; i<16; i++) {
        md5_bin_to_str(signature + 16 * i, temp);
        printf("%s\n", temp);
    }
#endif

    rsa_public_decrypt("public.key", 256, signature, sig_md5);
    md5_bin_to_str(sig_md5, temp);
    printf("sig_md5: %s\n", temp);
    if (memcmp(txt_md5, sig_md5, 16) != 0) {
        printf("signature check failed !\n");
    }

    return 0;
}

/*
生成私钥：
openssl genrsa -out private.key 2048 // for c
openssl pkcs8 -topk8 -in private.key -out pkcs8_private.key -nocrypt // for c and java

生成公钥：
openssl rsa -in private.key -out public.key -pubout // for java or c PEM_read_RSA_PUBKEY
openssl rsa -in private.key -out public.key -RSAPublicKey_out // for c PEM_read_RSAPublicKey
 */
