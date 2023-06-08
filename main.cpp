/*
 * @Author: zhzhou33
 * @Date: 2023-04-15 12:15:27
 * @LastEditors: zhzhou33
 * @LastEditTime: 2023-06-06 11:29:05
 */
#include "bn.h"
#include "ec.h"
#include "ossl_typ.h"
#include "RSignHelper.h"
#include "RSign.h"
#include <cstddef>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <chrono>
using namespace std;

int main()
{
    string dir = "../RSign/PKSK/pksk";
    RSignFunc *rsign = new RSignFunc(dir.c_str());
    /************************************************
    初始化部分,作为安全域CA,只持有自身公私钥对其他环成员的公钥
    ************************************************/
    //初始化 n 个公私钥对,存储到文件夹中
    // rsign->setup(30);

    // 读取 n 个公钥 和 CA 自身的 1 个私钥
    int n = 30;
    vector<EC_POINT *> PKSet(n);
    BIGNUM *sk = BN_new();

    for (int i = 1; i <= n; i++)
    {
        PKSet[i - 1] = EC_POINT_new(ec_group);
        load_hex2point(string(dir + "_" + to_string(i)).c_str(), PKSet[i - 1]);
    }
    //假设使用的是CA1的私钥
    load_hex2bn(string(dir + "_1").c_str(), sk);

    // 待签名公钥信息,固定长度 PK_LENGTH
    char *msg = EC_POINT_point2hex(ec_group, PKSet[0], POINT_CONVERSION_UNCOMPRESSED, nullptr);

    /************************************************
    环签名生成,输入待签名信息msg、环公钥集合PKSet、CA1自身的私钥sk
    输出环签名sign
    ************************************************/
    RSIGN *sign = rsign->RSign(msg, PKSet, sk);

    /************************************************
    作为CA生成环签名(证书)之后,需要发送给用户,用户从网络中接收并存储在本地文件中
    ************************************************/
    // save_rsign2hex("../RSign/sign/s1", sign);

    /************************************************
    作为用户,需要从文件中读取环签名(证书),发送给对方验证
    ************************************************/
    RSIGN *loadSign = nullptr;
    load_hex2rsign("../RSign/sign/s1", &loadSign);

    /************************************************
          验证方接收到用户的环签名(证书),执行验证算法
    ************************************************/
    loadSign->PKeys = PKSet;
    rsign->RVerify(loadSign);

    /************************************************
       验证方接收到多个用户的环签名(证书),执行批量验证算法
    ************************************************/
    vector<RSIGN *> signList;
    signList.push_back(loadSign);
    signList.push_back(loadSign);
    signList.push_back(loadSign);
    signList.push_back(loadSign);
    signList.push_back(loadSign);

    rsign->BatchRVerify(signList, PKSet);

    /************************************************
                        环签名更新
    ************************************************/
    loadSign->ca_pk = PKSet[0];
    loadSign->b = sign->b;
    EC_KEY *ec_key = nullptr;
    ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(ec_key);
    const EC_POINT *pk = EC_KEY_get0_public_key(ec_key);
    rsign->UpdateRSign(sign, const_cast<EC_POINT *>(pk), sk, true);
    rsign->UpdateRSign(sign, const_cast<EC_POINT *>(pk), sk, false);
    return 0;
}