/*
 * @Author: zhzhou33
 * @Date: 2023-04-15 21:24:24
 * @LastEditors: zhzhou33
 * @LastEditTime: 2023-05-21 10:00:45
 */
#include "RSignHelper.h"
#include "bn.h"
#include "ec.h"
#include "ossl_typ.h"
#include <cassert>
#include <cstring>
#include <fstream>
const EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
const EC_POINT *g = EC_GROUP_get0_generator(ec_group);
const BIGNUM *g_mod = EC_GROUP_get0_order(ec_group);

void KeyGen(const char *file)
{
    EC_KEY *ec_key = nullptr;
    ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(ec_key);
    const EC_POINT *pk = EC_KEY_get0_public_key(ec_key);
    const BIGNUM *sk = EC_KEY_get0_private_key(ec_key);

    // dump public key
    char *hex_pk = EC_POINT_point2hex(ec_group, pk, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    ofstream out(file, ios::out);
    out << hex_pk << endl;
    // dump private key
    char *hex_sk = BN_bn2hex(sk);
    out << hex_sk << endl;
    out.close();
    return;
}

void save_point2hex(const char *filename, const EC_POINT *point)
{
    // dump ecc point
    char *hex_pk = EC_POINT_point2hex(ec_group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    ofstream out(filename, ios::out);
    out << hex_pk << endl;
    out.close();
}

void save_bn2hex(const char *filename, const BIGNUM *bn)
{
    ofstream out(filename, ios::out);
    char *hex_sk = BN_bn2hex(bn);
    out << hex_sk << endl;
    out.close();
}

bool load_hex2point(const char *file, EC_POINT *pk)
{
    assert(pk);
    ifstream infile(file);
    if (!infile.is_open())
    {
        std::cout << "Failed to open file." << std::endl;
        return false;
    }
    string line;
    getline(infile, line);
    infile.close();
    EC_POINT_hex2point(ec_group, line.c_str(), pk, nullptr);
    return true;
}

bool load_hex2bn(const char *file, BIGNUM *sk)
{
    assert(sk);
    ifstream infile(file);
    if (!infile.is_open())
    {
        std::cout << "Failed to open file." << std::endl;
        return false;
    }
    string line;
    getline(infile, line);
    if (line.length() != SK_LENGTH)
        getline(infile, line);
    if (BN_hex2bn(&sk, line.c_str()) == 0)
    {
        printf("Error: Failed to convert hex string to BIGNUM\n");
        infile.close();
        BN_free(sk);
        return false;
    }
    infile.close();
    return true;
}

void print_hexbn(const BIGNUM *bn)
{
    char *hex_str = BN_bn2hex(bn);

    if (hex_str == NULL)
    {
        printf("Error: Failed to convert BIGNUM to string\n");
        return;
    }

    printf("BGNUM_HEX: %s\n", hex_str);

    OPENSSL_free(hex_str);
}

void print_hexpoint(const EC_POINT *point)
{
    char *hex_str = EC_POINT_point2hex(ec_group, point, POINT_CONVERSION_UNCOMPRESSED, NULL);

    if (hex_str == NULL)
    {
        printf("Error: Failed to convert EC_POINT to hex string\n");
        return;
    }

    printf("POINT_HEX: %s\n", hex_str);

    OPENSSL_free(hex_str);
}

void save_rsign2hex(const char *filename, RSIGN *sign)
{
    // ofstream out(filename, ios::out);
    FILE *fp = fopen(filename, "w");
    // out << sign->user_pk;
    fprintf(fp, "%s", sign->user_pk);
    for (auto &B : sign->B)
    {
        // dump ecc point
        char *hex_pk = EC_POINT_point2hex(ec_group, B, POINT_CONVERSION_UNCOMPRESSED, nullptr);
        // out << hex_pk;
        // cout << strlen(hex_pk) << endl;
        // fprintf(fp, "%s", hex_pk);
        fwrite(hex_pk, sizeof(char), PK_LENGTH, fp);
    }

    for (auto &r : sign->r)
    {
        char *hex_sk = BN_bn2hex(r);
        // cout << strlen(hex_sk) << endl;
        // fprintf(fp, "%s", hex_sk);
        fwrite(hex_sk, sizeof(char), SK_LENGTH, fp);
    }
    fclose(fp);
    return;
}

bool load_hex2rsign(const char *filename, RSIGN **sign)
{
    ifstream infile(filename);
    if (!infile.is_open())
    {
        std::cout << "Failed to open file." << std::endl;
        return false;
    }
    string line;
    getline(infile, line);
    cout << line.length() << endl;

    size_t cur = 0;
    int n = (line.length() - PK_LENGTH) / (PK_LENGTH + SK_LENGTH);
    *sign = new RSIGN(n);

    (*sign)->user_pk = new unsigned char[PK_LENGTH];
    memcpy((*sign)->user_pk, line.c_str(), PK_LENGTH);
    char temp[PK_LENGTH];
    for (int i = 0; i < n; i++)
    {
        (*sign)->B[i] = EC_POINT_new(ec_group);
        memcpy(temp, line.c_str() + PK_LENGTH * (i + 1), PK_LENGTH);
        EC_POINT_hex2point(ec_group, temp, (*sign)->B[i], nullptr);
        // print_hexpoint((*sign)->B[i]);
    }
    memset(temp, 0, PK_LENGTH);
    for (int i = 0; i < n; i++)
    {
        (*sign)->r[i] = BN_new();
        memcpy(temp, line.c_str() + PK_LENGTH * (n + 1) + SK_LENGTH * i, SK_LENGTH);
        BN_hex2bn(&(*sign)->r[i], temp);
        // print_hexbn((*sign)->r[i]);
    }

    infile.close();
    return true;
}
