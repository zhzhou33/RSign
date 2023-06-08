/*
 * @Author: zhzhou33
 * @Date: 2023-04-14 22:31:35
 * @LastEditors: zhzhou33
 * @LastEditTime: 2023-06-06 11:28:08
 */
#include "RSign.h"
#include "RSignHelper.h"
#include "ec.h"
#include "ossl_typ.h"
#include <cstring>

void RSignFunc::setup(int n)
{
    for (int i = 1; i <= n; i++)
    {
        KeyGen(string(m_load_path + "_" + to_string(i)).c_str());
    }
    return;
}

RSIGN *RSignFunc::RSign(char *msg, vector<EC_POINT *> &PKSet, const BIGNUM *sk)
{
    RSIGN *res = new RSIGN(PKSet.size());
    // Not Deap Copy
    res->user_pk = (unsigned char *)msg;
    for (int i = 0; i < PKSet.size(); i++)
        res->PKeys[i] = PKSet[i];
    res->ca_pk = res->PKeys[0];
    sortPK(res->PKeys);
    int skIndex = 0;
    for (int i = 0; i < res->PKeys.size(); i++)
    {
        if (res->PKeys[i] == res->ca_pk)
        {
            skIndex = i;
            break;
        }
    }
    // res->PKeys = PKSet;
    int n = PKSet.size();
    // B,C,r
    // res.B
    // vector<EC_POINT *> resB(n, NULL);
    vector<BIGNUM *> resC(n, NULL);
    // vector<BIGNUM *> resR(n, NULL);

    // B = b * g
    res->b = BN_new();
    //生成随机数
    BN_rand_range(res->b, g_mod);
    // EC_POINT *B = EC_POINT_new(ec_group);
    res->B[skIndex] = EC_POINT_new(ec_group);
    EC_POINT_mul(ec_group, res->B[skIndex], res->b, NULL, NULL, NULL);

    for (int i = skIndex + 1; i <= skIndex + n; i++)
    {
        // Ci = Hash(M||Bi-1)
        unsigned char *msg_and_B = (unsigned char *)malloc(PK_LENGTH + EC_POINT_point2oct(ec_group, res->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL));
        memcpy(msg_and_B, msg, PK_LENGTH);
        EC_POINT_point2oct(ec_group, res->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, &msg_and_B[PK_LENGTH], EC_POINT_point2oct(ec_group, res->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL), NULL);
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashlen;
        EVP_Digest(msg_and_B, PK_LENGTH + EC_POINT_point2oct(ec_group, res->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL), hash, &hashlen, HASH_ALGO, NULL);
        BIGNUM *C = BN_new();
        BN_bin2bn(hash, hashlen, C);
        resC[i % n] = C;
        // r = random
        res->r[i % n] = BN_new();
        //生成随机数
        BN_rand_range(res->r[i % n], g_mod);
        // r_G = r * g
        EC_POINT *r_G = EC_POINT_new(ec_group);
        EC_POINT_mul(ec_group, r_G, res->r[i % n], NULL, NULL, NULL);
        // c_PK = c * PK
        EC_POINT *c_PK = EC_POINT_new(ec_group);
        EC_POINT_mul(ec_group, c_PK, NULL, res->PKeys[i % n], C, NULL);
        // B = r_G - c_PK
        if (i < skIndex + n)
        {
            res->B[i % n] = EC_POINT_new(ec_group);
            EC_POINT_invert(ec_group, c_PK, NULL);
            EC_POINT_add(ec_group, res->B[i % n], r_G, c_PK, NULL);
        }
    }
    // r[0] = sk * c[0] + b
    BIGNUM *c_sk = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    BN_mod_mul(c_sk, sk, resC[skIndex], g_mod, bn_ctx);
    BN_mod_add(res->r[skIndex], c_sk, res->b, g_mod, bn_ctx);
    // check ring
    // r[0] * g
    EC_POINT *r0_G = EC_POINT_new(ec_group);
    EC_POINT_mul(ec_group, r0_G, res->r[skIndex], NULL, NULL, NULL);
    // c[0] * PK[0]
    EC_POINT *c0_PK0 = EC_POINT_new(ec_group);
    EC_POINT_mul(ec_group, c0_PK0, NULL, res->PKeys[skIndex], resC[skIndex], NULL);
    EC_POINT *R_right = EC_POINT_new(ec_group);
    EC_POINT_add(ec_group, R_right, res->B[skIndex], c0_PK0, NULL);
    if (EC_POINT_cmp(ec_group, R_right, r0_G, NULL) != 0)
    {
        cout << "False" << endl;
        return nullptr;
    }
    return res;
}

bool RSignFunc::RVerify(RSIGN *sign)
{
    int n = sign->PKeys.size();
    sortPK(sign->PKeys);
    EC_POINT *preB = sign->B[0];
    EC_POINT *curB = EC_POINT_new(ec_group);
    BIGNUM *c = BN_new();
    for (int i = 1; i <= n; i++)
    {
        // c[i] = Hash(M || B[i-1])
        unsigned char *msg_and_B = (unsigned char *)malloc(PK_LENGTH + EC_POINT_point2oct(ec_group, preB, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL));
        memcpy(msg_and_B, sign->user_pk, PK_LENGTH);
        EC_POINT_point2oct(ec_group, preB, POINT_CONVERSION_UNCOMPRESSED, &msg_and_B[PK_LENGTH], EC_POINT_point2oct(ec_group, preB, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL), NULL);
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashlen;
        EVP_Digest(msg_and_B, PK_LENGTH + EC_POINT_point2oct(ec_group, preB, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL), hash, &hashlen, HASH_ALGO, NULL);
        BN_bin2bn(hash, hashlen, c);
        // resC[i % n] = C;
        // r[i] * g
        EC_POINT *r_G = EC_POINT_new(ec_group);
        EC_POINT_mul(ec_group, r_G, sign->r[i % n], NULL, NULL, NULL);
        // c * PK
        EC_POINT *c_PK = EC_POINT_new(ec_group);
        EC_POINT_mul(ec_group, c_PK, NULL, sign->PKeys[i % n], c, NULL);
        // r_G - c_PK
        curB = EC_POINT_new(ec_group);
        EC_POINT_invert(ec_group, c_PK, NULL);
        EC_POINT_add(ec_group, curB, r_G, c_PK, NULL);
        // delete curB
        if (EC_POINT_cmp(ec_group, curB, sign->B[i % n], NULL) != 0)
        {
            cout << "error" << endl;
            return false;
        }
        preB = curB;
    }
    cout << "Success" << endl;
    return true;
}

bool RSignFunc::BatchRVerify(vector<RSIGN *> &signList, vector<EC_POINT *> &PKSet)
{
    if (signList.size() == 0)
        return false;
    int numsOfSigns = signList.size();
    int numsOfParams = signList[0]->PKeys.size();
    // copy
    vector<EC_POINT *> sumOfBCol(numsOfParams);
    vector<BIGNUM *> sumOfRCol(numsOfParams);
    vector<BIGNUM *> sumOfCCol(numsOfParams, 0);
    //深拷贝
    for (size_t i = 0; i < numsOfParams; ++i)
    {
        sumOfBCol[i] = EC_POINT_dup(signList[0]->B[i], ec_group);
        sumOfRCol[i] = BN_dup(signList[0]->r[i]);
        sumOfCCol[i] = BN_new();
    }
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *c = BN_new();

    int saltIndex = rand() % numsOfParams;
    BIGNUM *k = BN_new();

    EC_POINT *r_G = EC_POINT_new(ec_group);
    EC_POINT *c_PK = EC_POINT_new(ec_group);
    EC_POINT *result = EC_POINT_new(ec_group);
    vector<BIGNUM *> cCol(numsOfSigns, 0);
    sortPK(PKSet);
    for (int j = 0; j < numsOfParams; j++)
    {
        for (int i = 0; i < numsOfSigns; i++)
        {
            // H(M||B)
            // c[i] = Hash(M || B[i-1])
            size_t msglen = PK_LENGTH;
            const EC_POINT *preB = signList[i]->B[((j - 1) % numsOfParams + numsOfParams) % numsOfParams];
            unsigned char *msg_and_B = (unsigned char *)malloc(msglen + EC_POINT_point2oct(ec_group, preB, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL));
            memcpy(msg_and_B, signList[i]->user_pk, msglen);
            EC_POINT_point2oct(ec_group, preB, POINT_CONVERSION_UNCOMPRESSED, &msg_and_B[msglen], EC_POINT_point2oct(ec_group, preB, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL), NULL);
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hashlen;
            EVP_Digest(msg_and_B, msglen + EC_POINT_point2oct(ec_group, preB, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL), hash, &hashlen, HASH_ALGO, NULL);
            BN_bin2bn(hash, hashlen, c);
            //
            BN_mod_add(sumOfCCol[j], sumOfCCol[j], c, g_mod, bn_ctx);

            cCol[i] = c;
            if (i == 0)
                continue;
            auto P1 = sumOfBCol[j];
            auto P2 = signList[i]->B[j];
            EC_POINT_add(ec_group, sumOfBCol[j], P1, P2, NULL);
            // print_bn(sumOfRCol[j]);
            // print_bn(signs[i].second[j]);
            BN_mod_add(sumOfRCol[j], sumOfRCol[j], signList[i]->r[j], g_mod, bn_ctx);
        }
        // 随机选择 n 个参数列表col中的任意一列 saltIndex,计算
        if (j == saltIndex)
        {
            // k1 * B1 + k2 * B2 +... == k1 * (r_G-c_Pk) + ...
            EC_POINT *left = EC_POINT_new(ec_group);
            EC_POINT *right = EC_POINT_new(ec_group);
            for (int i = 0; i < numsOfSigns; i++)
            {
                // 生成随机数
                BN_rand_range(k, g_mod);
                // 计算 k * B_i_saltIndex 计算 k乘上第i个环签名的第saltIndex的B值
                EC_POINT_mul(ec_group, result, NULL, signList[i]->B[saltIndex], k, NULL);
                // 累加
                EC_POINT_add(ec_group, left, left, result, NULL);

                // r * g 计算第i个环签名的第saltIndex的r乘上g
                EC_POINT_mul(ec_group, r_G, signList[i]->r[saltIndex], NULL, NULL, NULL);
                // c * PK 计算第i个环签名的第saltIndex的c乘上公钥PK
                // cCol 记录了当前saltIndex列的c值
                EC_POINT_mul(ec_group, c_PK, NULL, PKSet[saltIndex], cCol[i], NULL);
                // 计算 r_G - c_Pk
                EC_POINT_invert(ec_group, c_PK, NULL);
                EC_POINT_add(ec_group, result, r_G, c_PK, NULL);
                // 计算 k *(r_G-c_Pk)
                EC_POINT_mul(ec_group, result, NULL, result, k, NULL);
                // 累加
                EC_POINT_add(ec_group, right, right, result, NULL);
            }
            // 验证左式是否等于右式
            if (EC_POINT_cmp(ec_group, left, right, NULL) != 0)
            {
                cout << "error" << endl;
                return false;
            }
        }
        else
        {
            // r * g
            EC_POINT_mul(ec_group, r_G, sumOfRCol[j % numsOfParams], NULL, NULL, NULL);
            // c * PK
            EC_POINT_mul(ec_group, c_PK, NULL, PKSet[j % numsOfParams], sumOfCCol[j % numsOfParams], NULL);

            EC_POINT_invert(ec_group, c_PK, NULL);
            EC_POINT_add(ec_group, result, r_G, c_PK, NULL);
            if (EC_POINT_cmp(ec_group, result, sumOfBCol[j % numsOfParams], NULL) != 0)
            {
                cout << "error" << endl;
                return false;
            }
        }
    }

    cout << "BatchRVerifyAccess!" << endl;

    return true;
    /* EC_POINT_free(r_G);
    EC_POINT_free(c_PK);
    EC_POINT_free(result);
    BN_free(c);
    BN_CTX_free(bn_ctx); */
}
// 调用该接口前,公钥集合需要提前排好序
int RSignFunc::UpdateRPKset(vector<EC_POINT *> &PKSet, EC_POINT *updatePK, bool kind)
{
    int index = -1;
    // add new
    if (kind == true)
    {
        const char *hex_newPK = EC_POINT_point2hex(ec_group, updatePK, POINT_CONVERSION_UNCOMPRESSED, nullptr);
        //  cout << hex_newPK << endl;
        index = PKSet.size() - 1;
        for (int i = 0; i < PKSet.size(); i++)
        {
            const char *hex_point = EC_POINT_point2hex(ec_group, PKSet[i], POINT_CONVERSION_UNCOMPRESSED, nullptr);
            //  插入位置,第一个小于数组字符串的位置
            if (strcmp(hex_newPK, hex_point) < 0)
            {
                PKSet.insert(PKSet.begin() + i, updatePK);
                index = i;
                break;
            }
        }
    }
    // delete pk
    else
    {
        for (int i = 0; i < PKSet.size(); i++)
        {
            if (EC_POINT_cmp(ec_group, PKSet[i], updatePK, nullptr) == 0)
            {
                PKSet.erase(PKSet.begin() + i);
                index = i;
                break;
            }
        }
    }
    return index;
}

void RSignFunc::sortPK(vector<EC_POINT *> &PKSet)
{
    // 升序排序,以转换后字符串形式进行排序
    // 也可以考虑直接使用 EC_POINT_cmp,以椭圆曲线形式进行排序
    sort(PKSet.begin(), PKSet.end(), [&](EC_POINT *a, EC_POINT *b)
         {
            const char *hex_a = EC_POINT_point2hex(ec_group, a, POINT_CONVERSION_UNCOMPRESSED, nullptr);
            const char *hex_b = EC_POINT_point2hex(ec_group, b, POINT_CONVERSION_UNCOMPRESSED, nullptr);
            return strcmp(hex_a, hex_b)<0; });
    return;
}
RSIGN *RSignFunc::addRSignature(RSIGN *sign, EC_POINT *newPK, const BIGNUM *sk)
{
    int insertIndex = UpdateRPKset(sign->PKeys, newPK, true);

    // newPk 插入正确位置
    int n = sign->PKeys.size();
    BIGNUM *C = BN_new();
    for (int i = insertIndex; i < insertIndex + n; i++)
    {
        if (EC_POINT_cmp(ec_group, sign->PKeys[i % n], sign->ca_pk, nullptr) == 0)
        {
            // r[0] = sk * c[0] + b
            BIGNUM *c_sk = BN_new();
            BN_CTX *bn_ctx = BN_CTX_new();
            BN_mod_mul(c_sk, sk, C, g_mod, bn_ctx);
            BN_mod_add(sign->r[i % n], c_sk, sign->b, g_mod, bn_ctx);
            // check ring
            // r[0] * g
            EC_POINT *r0_G = EC_POINT_new(ec_group);
            EC_POINT_mul(ec_group, r0_G, sign->r[i % n], NULL, NULL, NULL);
            // c[0] * PK[0]
            EC_POINT *c0_PK0 = EC_POINT_new(ec_group);
            EC_POINT_mul(ec_group, c0_PK0, NULL, sign->PKeys[i % n], C, NULL);
            EC_POINT *R_right = EC_POINT_new(ec_group);
            EC_POINT_add(ec_group, R_right, sign->B[i % n], c0_PK0, NULL);
            if (EC_POINT_cmp(ec_group, R_right, r0_G, NULL) != 0)
            {
                cout << "AddRSignature Faild!" << endl;
                return nullptr;
            }
            else
            {
                cout << "AddRSignature Success!" << endl;
                return sign;
            }
        }
        else
        {
            // Ci = Hash(M||Bi-1)
            unsigned char *msg_and_B = (unsigned char *)malloc(PK_LENGTH + EC_POINT_point2oct(ec_group, sign->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL));
            memcpy(msg_and_B, sign->user_pk, PK_LENGTH);
            EC_POINT_point2oct(ec_group, sign->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, &msg_and_B[PK_LENGTH], EC_POINT_point2oct(ec_group, sign->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL), NULL);
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hashlen;
            EVP_Digest(msg_and_B, PK_LENGTH + EC_POINT_point2oct(ec_group, sign->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL), hash, &hashlen, HASH_ALGO, NULL);
            BIGNUM *C = BN_new();
            BN_bin2bn(hash, hashlen, C);
            // r = random
            sign->r[i % n] = BN_new();
            //生成随机数
            BN_rand_range(sign->r[i % n], g_mod);
            // r_G = r * g
            EC_POINT *r_G = EC_POINT_new(ec_group);
            EC_POINT_mul(ec_group, r_G, sign->r[i % n], NULL, NULL, NULL);
            // c_PK = c * PK
            EC_POINT *c_PK = EC_POINT_new(ec_group);
            EC_POINT_mul(ec_group, c_PK, NULL, sign->PKeys[i % n], C, NULL);
            // B = r_G - c_PK
            if (i < insertIndex + n)
            {
                sign->B[i % n] = EC_POINT_new(ec_group);
                EC_POINT_invert(ec_group, c_PK, NULL);
                EC_POINT_add(ec_group, sign->B[i % n], r_G, c_PK, NULL);
            }
        }
    }
    return nullptr;
}

RSIGN *RSignFunc::deleteRSignature(RSIGN *sign, EC_POINT *newPK, const BIGNUM *sk)
{
    int deleteIndex = UpdateRPKset(sign->PKeys, newPK, false);

    if (deleteIndex == -1)
        return nullptr;
    if (deleteIndex == 0)
        return this->RSign((char *)sign->user_pk, sign->PKeys, sk);
    int n = sign->PKeys.size();
    BIGNUM *C = BN_new();
    for (int i = deleteIndex; i < deleteIndex + n; i++)
    {
        if (EC_POINT_cmp(ec_group, sign->PKeys[i % n], sign->ca_pk, nullptr) == 0)
        {
            // r[0] = sk * c[0] + b
            BIGNUM *c_sk = BN_new();
            BN_CTX *bn_ctx = BN_CTX_new();
            BN_mod_mul(c_sk, sk, C, g_mod, bn_ctx);
            BN_mod_add(sign->r[i % n], c_sk, sign->b, g_mod, bn_ctx);
            // check ring
            // r[0] * g
            EC_POINT *r0_G = EC_POINT_new(ec_group);
            EC_POINT_mul(ec_group, r0_G, sign->r[i % n], NULL, NULL, NULL);
            // c[0] * PK[0]
            EC_POINT *c0_PK0 = EC_POINT_new(ec_group);
            EC_POINT_mul(ec_group, c0_PK0, NULL, sign->PKeys[i % n], C, NULL);
            EC_POINT *R_right = EC_POINT_new(ec_group);
            EC_POINT_add(ec_group, R_right, sign->B[i % n], c0_PK0, NULL);
            if (EC_POINT_cmp(ec_group, R_right, r0_G, NULL) != 0)
            {
                cout << "deleteRSignature Faild!" << endl;
                return nullptr;
            }
            else
            {
                cout << "deleteRSignature Success!" << endl;
                return sign;
            }
        }
        else
        {
            // Ci = Hash(M||Bi-1)
            unsigned char *msg_and_B = (unsigned char *)malloc(PK_LENGTH + EC_POINT_point2oct(ec_group, sign->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL));
            memcpy(msg_and_B, sign->user_pk, PK_LENGTH);
            EC_POINT_point2oct(ec_group, sign->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, &msg_and_B[PK_LENGTH], EC_POINT_point2oct(ec_group, sign->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL), NULL);
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hashlen;
            EVP_Digest(msg_and_B, PK_LENGTH + EC_POINT_point2oct(ec_group, sign->B[(i - 1) % n], POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL), hash, &hashlen, HASH_ALGO, NULL);
            BIGNUM *C = BN_new();
            BN_bin2bn(hash, hashlen, C);
            // r = random
            sign->r[i % n] = BN_new();
            //生成随机数
            BN_rand_range(sign->r[i % n], g_mod);
            // r_G = r * g
            EC_POINT *r_G = EC_POINT_new(ec_group);
            EC_POINT_mul(ec_group, r_G, sign->r[i % n], NULL, NULL, NULL);
            // c_PK = c * PK
            EC_POINT *c_PK = EC_POINT_new(ec_group);
            EC_POINT_mul(ec_group, c_PK, NULL, sign->PKeys[i % n], C, NULL);
            // B = r_G - c_PK
            if (i < deleteIndex + n)
            {
                sign->B[i % n] = EC_POINT_new(ec_group);
                EC_POINT_invert(ec_group, c_PK, NULL);
                EC_POINT_add(ec_group, sign->B[i % n], r_G, c_PK, NULL);
            }
        }
    }
    return nullptr;
}

RSIGN *RSignFunc::UpdateRSign(RSIGN *sign, EC_POINT *updatePK, const BIGNUM *sk, bool kind)
{
    sortPK(sign->PKeys);
    // kind == true, 新增
    if (kind)
        return addRSignature(sign, updatePK, sk);
    return deleteRSignature(sign, updatePK, sk);
}
