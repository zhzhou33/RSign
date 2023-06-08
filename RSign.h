/*
 * @Author: zhzhou33
 * @Date: 2023-05-17 16:00:26
 * @LastEditors: zhzhou33
 * @LastEditTime: 2023-06-06 11:27:54
 */
#pragma once
#include "RSignHelper.h"
#include "ec.h"
#include "ossl_typ.h"

struct RSIGN;
class RSignFunc
{
public:
    RSignFunc(const char *path) :
        m_load_path(path)
    {
    }
    void setup(int n);

    RSIGN *RSign(char *msg, vector<EC_POINT *> &PKSet, const BIGNUM *sk);

    bool RVerify(RSIGN *sign);

    bool BatchRVerify(vector<RSIGN *> &signList,vector<EC_POINT *> &PKSet);

    int UpdateRPKset(vector<EC_POINT *> &PKSet, EC_POINT *updatePK, bool kind);

    RSIGN* UpdateRSign(RSIGN *sign, EC_POINT *updatePK, const BIGNUM *sk, bool kind);

private:
    void sortPK(vector<EC_POINT *> &PKSet);

    RSIGN* deleteRSignature(RSIGN *sign, EC_POINT *newPK, const BIGNUM *sk);

    RSIGN* addRSignature(RSIGN *sign, EC_POINT *newPK, const BIGNUM *sk);

private:
    string m_load_path;
};