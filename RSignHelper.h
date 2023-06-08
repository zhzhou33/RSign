/*
 * @Author: zhzhou33
 * @Date: 2023-04-15 21:36:14
 * @LastEditors: zhzhou33
 * @LastEditTime: 2023-05-29 14:54:44
 */
#pragma once
// #include "RSign.h"
#include "bn.h"
#include "ossl_typ.h"
#include <cstddef>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <assert.h>
using namespace std;
#define HASH_ALGO EVP_sha256()
extern const EC_GROUP *ec_group;
extern const EC_POINT *g;
extern const BIGNUM *g_mod;

#define PK_LENGTH 130
#define SK_LENGTH 64

/*
    环签名的输入结构为: = (M,B1,B2,...,Bn,r1,r2,...rn)
    其中,M为待签名的信息,B的结构为椭圆曲线上的点,r为椭圆曲线上的 BIGNUM
    除此之外,为了实现环签名快速更新的功能,需要由CA存储生成该环签名的 b
*/
struct RSIGN
{
    BIGNUM *b;                // 用于快速更新的 b
    unsigned char *user_pk;   // 用户公钥
    vector<EC_POINT *> B;     // B1~Bn
    vector<BIGNUM *> r;       // r1~rn
    vector<EC_POINT *> PKeys; // 该环签名生成是所使用的环公钥集合
    EC_POINT *ca_pk;

    RSIGN(int num) :
        // r 数组不需要提前分配空间,在生成环签名时会为其分配空间
        user_pk(nullptr), B(num, NULL), r(num, NULL), PKeys(num, NULL), ca_pk(NULL)
    {
    }

    ~RSIGN()
    {
        BN_free(b);
        delete[] user_pk;
        for (int i = 0; i < B.size(); i++)
        {
            EC_POINT_free(B[i]);
            BN_free(r[i]);
            EC_POINT_free(PKeys[i]);
        }
    }
};

/*
    基本功能接口
*/
// 初始化公私钥对,存储到对应文件夹 file_path 中
void KeyGen(const char *file_path);

// 读取文件中的公钥(椭圆曲线上的点)到 EC_POINT* pk 中,使用前 pk 需要分配内存
bool load_hex2point(const char *file, EC_POINT *pk);

//读取文件中的 BIGNUM 到内存中, sk 使用前需要分配内存
bool load_hex2bn(const char *file, BIGNUM *sk);

// 将椭圆曲线上的点保存到文件中
void save_point2hex(const char *filename, const EC_POINT *point);

// 将 BIGNUM 的值保存到文件中
void save_bn2hex(const char *filename, const BIGNUM *bn);

// 打印 BIGNUM 的 hex 值
void print_hexbn(const BIGNUM *bn);

// 打印 point 的 hex 值
void print_hexpoint(const EC_POINT *point);

void save_rsign2hex(const char *filename, RSIGN *sign);

bool load_hex2rsign(const char *filename, RSIGN **sign);
