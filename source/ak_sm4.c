//
// Created by Никита Юрасов on 13.12.2020.
//
#include <ak_tools.h>
#include <ak_bckey.h>

/* ---------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H

#include <stdlib.h>

#else
#error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H

#include <string.h>

#else
#error Library cannot be compiled without string.h header
#endif

#define SM4_KEY_SCHEDULE  32

#define SM4_ONE_ROUND(k0, k1, k2, k3, F)                                            \
  do {                                                                         \
    B0 ^= F(B1 ^ B2 ^ B3 ^ ks.rk[k0]);                                         \
    B1 ^= F(B0 ^ B2 ^ B3 ^ ks.rk[k1]);                                         \
    B2 ^= F(B0 ^ B1 ^ B3 ^ ks.rk[k2]);                                         \
    B3 ^= F(B0 ^ B1 ^ B2 ^ ks.rk[k3]);                                         \
  } while (0)


const static ak_uint32 FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

const static ak_uint32 CK[32] = {
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

static const ak_uint8 sm4_sbox[256] = {
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
        0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
        0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
        0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
        0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
        0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
        0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
        0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
        0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
        0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
        0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
        0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
        0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
        0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
        0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
        0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
        0xD7, 0xCB, 0x39, 0x48};


typedef struct key_struct {
    ak_uint32 rk[32];
} sm4_key;

static ak_uint32 left_rotation(ak_uint32 a, ak_uint8 n) { return (a << n) | (a >> (32 - n)); }

static ak_uint32 hexArrayToWord(const ak_uint8 *b, ak_uint32 n) {
    return ((ak_uint32) b[4 * n] << 24) | ((ak_uint32) b[4 * n + 1] << 16) |
           ((ak_uint32) b[4 * n + 2] << 8) | ((ak_uint32) b[4 * n + 3]);
}

static void WordToHexArray(ak_uint32 v, ak_uint8 *b) {
    b[0] = (ak_uint8) (v >> 24);
    b[1] = (ak_uint8) (v >> 16);
    b[2] = (ak_uint8) (v >> 8);
    b[3] = (ak_uint8) (v);
}

static ak_uint32 sm4_T(ak_uint32 X) {
    ak_uint32 t = 0;

    t |= ((ak_uint32) sm4_sbox[(ak_uint8) (X >> 24)]) << 24;
    t |= ((ak_uint32) sm4_sbox[(ak_uint8) (X >> 16)]) << 16;
    t |= ((ak_uint32) sm4_sbox[(ak_uint8) (X >> 8)]) << 8;
    t |= sm4_sbox[(ak_uint8) X];

    return t ^ left_rotation(t, 2) ^ left_rotation(t, 10) ^ left_rotation(t, 18) ^ left_rotation(t, 24);
}

int sm4_set_key(const ak_uint8 *key, sm4_key *ks) {
    ak_uint32 K[4];
    int i;

    K[0] = hexArrayToWord(key, 0) ^ FK[0];
    K[1] = hexArrayToWord(key, 1) ^ FK[1];
    K[2] = hexArrayToWord(key, 2) ^ FK[2];
    K[3] = hexArrayToWord(key, 3) ^ FK[3];

    for (i = 0; i != SM4_KEY_SCHEDULE; ++i) {
        ak_uint32 X = K[(i + 1) % 4] ^K[(i + 2) % 4] ^K[(i + 3) % 4] ^CK[i];
        ak_uint32 t = 0;

        t |= ((ak_uint32) sm4_sbox[(ak_uint8) (X >> 24)]) << 24;
        t |= ((ak_uint32) sm4_sbox[(ak_uint8) (X >> 16)]) << 16;
        t |= ((ak_uint32) sm4_sbox[(ak_uint8) (X >> 8)]) << 8;
        t |= sm4_sbox[(ak_uint8) X];

        t = t ^ left_rotation(t, 13) ^ left_rotation(t, 23);
        K[i % 4] ^= t;
        ks->rk[i] = K[i % 4];
    }
    return 1;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция зашифрования одного блока информации
    @param skey Контекст секретного ключа.
    @param in Блок входной информации (открытый текст).
    @param out Блок выходной информации (шифртекст). */
/* ----------------------------------------------------------------------------------------------- */
static void ak_sm4_encrypt(ak_skey skey, ak_pointer in, ak_pointer out) {
    ak_uint32 B0 = hexArrayToWord(in, 0);
    ak_uint32 B1 = hexArrayToWord(in, 1);
    ak_uint32 B2 = hexArrayToWord(in, 2);
    ak_uint32 B3 = hexArrayToWord(in, 3);

    sm4_key ks;
    sm4_set_key(skey->key, &ks);

    SM4_ONE_ROUND(0, 1, 2, 3, sm4_T);
    SM4_ONE_ROUND(4, 5, 6, 7, sm4_T);
    SM4_ONE_ROUND(8, 9, 10, 11, sm4_T);
    SM4_ONE_ROUND(12, 13, 14, 15, sm4_T);
    SM4_ONE_ROUND(16, 17, 18, 19, sm4_T);
    SM4_ONE_ROUND(20, 21, 22, 23, sm4_T);
    SM4_ONE_ROUND(24, 25, 26, 27, sm4_T);
    SM4_ONE_ROUND(28, 29, 30, 31, sm4_T);

    WordToHexArray(B3, (ak_uint8 *) out);
    WordToHexArray(B2, (ak_uint8 *) out + 4);
    WordToHexArray(B1, (ak_uint8 *) out + 8);
    WordToHexArray(B0, (ak_uint8 *) out + 12);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция расшифрования одного блока информации
    @param skey Контекст секретного ключа.
    @param in Блок входной информации (шифртекст).
    @param out Блок выходной информации (открытый текст). */
/* ----------------------------------------------------------------------------------------------- */
static void ak_sm4_decrypt(ak_skey skey, ak_pointer in, ak_pointer out) {
    ak_uint32 B0 = hexArrayToWord(in, 0);
    ak_uint32 B1 = hexArrayToWord(in, 1);
    ak_uint32 B2 = hexArrayToWord(in, 2);
    ak_uint32 B3 = hexArrayToWord(in, 3);

    sm4_key ks;
    sm4_set_key(skey->key, &ks);

    SM4_ONE_ROUND(31, 30, 29, 28, sm4_T);
    SM4_ONE_ROUND(27, 26, 25, 24, sm4_T);
    SM4_ONE_ROUND(23, 22, 21, 20, sm4_T);
    SM4_ONE_ROUND(19, 18, 17, 16, sm4_T);
    SM4_ONE_ROUND(15, 14, 13, 12, sm4_T);
    SM4_ONE_ROUND(11, 10, 9, 8, sm4_T);
    SM4_ONE_ROUND(7, 6, 5, 4, sm4_T);
    SM4_ONE_ROUND(3, 2, 1, 0, sm4_T);

    WordToHexArray(B3, (ak_uint8 *) out);
    WordToHexArray(B2, (ak_uint8 *) out + 4);
    WordToHexArray(B1, (ak_uint8 *) out + 8);
    WordToHexArray(B0, (ak_uint8 *) out + 12);
}

/*!
 * \brief Функция освобождает память, занимаемую развернутыми ключами алгоритма SM4.
 * \param skey Указатель на контекст секретного ключа, содержащего
 * развернутые раундовые ключи и маски.
 * \return Функция возвращает \ref ak_error_ok в случае успеха.
 * В противном случае возвращается код ошибки.
*/
static int ak_sm4_delete_keys(ak_skey skey) {
    int error = ak_error_ok;

    /* выполняем стандартные проверки */
    if (skey == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using a null pointer to secret key");
    if (skey->data != NULL) {
        /* теперь очистка и освобождение памяти */
        if ((error = ak_ptr_context_wipe(skey->data, sizeof(sm4_key),
                                         &skey->generator)) != ak_error_ok) {
            ak_error_message(error, __func__, "incorrect wiping an internal data");
            memset(skey->data, 0, sizeof(sm4_key));
        }
        free(skey->data);
        skey->data = NULL;
    }
    return error;
}

static int ak_skey_context_mask_none(ak_skey skey) { return ak_error_ok; }

static int ak_skey_context_unmask_none(ak_skey skey) { return ak_error_ok; }

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализируете контекст ключа алгоритма блочного шифрования SM4
    После инициализации устанавливаются обработчики (функции класса). Однако
   само значение ключу не присваивается - поле `bkey->key` остается
   неопределенным.
    @param bkey Контекст секретного ключа алгоритма блочного шифрования.
    @return Функция возвращает код ошибки. В случаее успеха возвращается \ref
   ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_context_create_sm4(ak_bckey bkey) {
    int error = ak_error_ok;

    if (bkey == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                "using null pointer to block cipher key context");

    /* создаем ключ алгоритма шифрования и определяем его методы */
    if ((error = ak_bckey_context_create(bkey, 16, 16)) != ak_error_ok)
        return ak_error_message(error, __func__,
                                "wrong initialization of block cipher key context");

    /* устанавливаем OID алгоритма шифрования */
    if ((bkey->key.oid = ak_oid_context_find_by_name("sm4")) == NULL) {
        error = ak_error_get_value();
        ak_error_message(error, __func__,
                         "wrong search of predefined sm4 block cipher OID");
        ak_bckey_context_destroy(bkey);
        return error;
    }

    /* ресурс ключа устанавливается в момент присвоения ключа */

    /* устанавливаем методы */
    bkey->key.set_mask = ak_skey_context_mask_none;
    bkey->key.unmask = ak_skey_context_unmask_none;
    bkey->delete_keys = ak_sm4_delete_keys;
    bkey->encrypt = ak_sm4_encrypt;
    bkey->decrypt = ak_sm4_decrypt;
    return error;
}


/* Функция сложения по модулю 2 поэлементно двух массивов */
static void xor(ak_const_pointer arr1, ak_const_pointer arr2, ak_pointer out, size_t size){
    const ak_uint8 *left = arr1;
    const ak_uint8 *right = arr2;
    ak_uint8 *myout = out;
    for (int i=0; i< size; ++i){
        myout[i] = left[i] ^ right[i];
    }
}

/* ----------------------------------------------------------------------------------------------- */
bool_t ak_bckey_test_sm4(void) {
    int audit = ak_log_get_level();

    /* значение секретного ключа */
    ak_uint8 key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

    /* открытый текст для режимов ECB, CBC, OFB, CFB */
    ak_uint8 in[32] = {0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
                       0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD,
                       0xEE, 0xEE, 0xEE, 0xEE, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB};

    /* зашифрованный текст <in> режимом ECB */
    ak_uint8 outecb[32] = {0x5E, 0xC8, 0x14, 0x3D, 0xE5, 0x09, 0xCF, 0xF7,
                           0xB5, 0x17, 0x9F, 0x8F, 0x47, 0x4B, 0x86, 0x19,
                           0x2F, 0x1D, 0x30, 0x5A, 0x7F, 0xB1, 0x7D, 0xF9,
                           0x85, 0xF8, 0x1C, 0x84, 0x82, 0x19, 0x23, 0x04};

    /* вектор инициализации для режима CBC */
    ak_uint8 ivcbc[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    /* зашифрованный тест <in> режимом CBC */
    ak_uint8 outcbc[32] = {0x78, 0xEB, 0xB1, 0x1C, 0xC4, 0x0B, 0x0A, 0x48,
                           0x31, 0x2A, 0xAE, 0xB2, 0x04, 0x02, 0x44, 0xCB,
                           0x4C, 0xB7, 0x01, 0x69, 0x51, 0x90, 0x92, 0x26,
                           0x97, 0x9B, 0x0D, 0x15, 0xDC, 0x6A, 0x8F, 0x6D};

    /* открытый текст для режима CTR */
    ak_uint8 inctr[16] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                          0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};

    /* вектор инициализации для режима CTR*/
    ak_uint8 ivctr[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    /* зашифрованный текст режимом CTR */
    ak_uint8 outctr[16] = {0xAC, 0x32, 0x36, 0xCB, 0x97, 0x0C, 0xC2, 0x07,
                           0x91, 0x36, 0x4C, 0x39, 0x5A, 0x13, 0x42, 0xD1};


    struct bckey bkey;
    ak_uint8 myout[256];
    bool_t result = ak_true;
    int error = ak_error_ok;

    /* 1. Создаем контекст ключа алгоритма SM4 и устанавливаем значение ключа */
    if ((error = ak_bckey_context_create_sm4(&bkey)) != ak_error_ok) {
        ak_error_message(error, __func__,
                         "incorrect initialization of sm4 secret key context");
        return ak_false;
    }
    if ((error = ak_bckey_context_set_key(&bkey, key, sizeof(key))) !=
        ak_error_ok) {
        ak_error_message(error, __func__, "wrong creation of test key");
        result = ak_false;
        goto exit;
    }

    /* 2. Проверяем корректность работы шифра в режиме ECB */
    if ((error = ak_bckey_context_encrypt_ecb(&bkey, in, myout, sizeof(in))) !=
        ak_error_ok) {
        ak_error_message(error, __func__, "wrong ecb mode encryption");
        result = ak_false;
        goto exit;
    }
    if (!ak_ptr_is_equal_with_log(myout, outecb, sizeof(outecb))) {
        ak_error_message(ak_error_not_equal_data, __func__,
                         "the ecb mode encryption test from SM4 is wrong");
        result = ak_false;
        goto exit;
    }

    if ((error = ak_bckey_context_decrypt_ecb(&bkey, outecb, myout,
                                              sizeof(outecb))) != ak_error_ok) {
        ak_error_message(error, __func__, "wrong ecb mode decryption");
        result = ak_false;
        goto exit;
    }
    if (!ak_ptr_is_equal_with_log(myout, in, sizeof(in))) {
        ak_error_message(ak_error_not_equal_data, __func__,
                         "the ecb mode decryption test from SM4 is wrong");
        result = ak_false;
        goto exit;
    }
    if (audit >= ak_log_maximum)
        ak_error_message(ak_error_ok, __func__,
                         "the ecb mode encryption/decryption test from SM4 is Ok");

    /* 3. Проверяем корректность работы шифра в режиме CBC */
    if ((error = ak_bckey_context_encrypt_cbc(&bkey, in, myout, sizeof(in), ivcbc, sizeof(ivcbc))) !=
        ak_error_ok) {
        ak_error_message(error, __func__, "wrong ccb mode encryption");
        result = ak_false;
        goto exit;
    }
    if (!ak_ptr_is_equal_with_log(myout, outcbc, sizeof(outcbc))) {
        ak_error_message(ak_error_not_equal_data, __func__,
                         "the cbc mode encryption test from SM4 is wrong");
        result = ak_false;
        goto exit;
    }

    if ((error = ak_bckey_context_decrypt_cbc(&bkey, outcbc, myout,
                                              sizeof(outcbc), ivcbc, sizeof(ivcbc))) != ak_error_ok) {
        ak_error_message(error, __func__, "wrong cbc mode decryption");
        result = ak_false;
        goto exit;
    }
    if (!ak_ptr_is_equal_with_log(myout, in, sizeof(in))) {
        ak_error_message(ak_error_not_equal_data, __func__,
                         "the ecb mode decryption test from SM4 is wrong");
        result = ak_false;
        goto exit;
    }
    if (audit >= ak_log_maximum)
        ak_error_message(ak_error_ok, __func__,
                         "the ecb mode encryption/decryption test from SM4 is Ok");

    /* 4. Проверяем коррекность работы в режиме CTR */
    /* Проверка осуществляется следующим образом: шифруется IV длиной в один блок и складывается по модулю 2 с блоком
     * открытого текста. Результирующий блок -- это один зашифрованный блок режимом CTR*/

    if ((error = ak_bckey_context_encrypt_ecb(&bkey, ivctr, myout, sizeof(ivctr))) !=
        ak_error_ok) {
        ak_error_message(error, __func__, "wrong ecb mode encryption of iv for ctr mode");
        result = ak_false;
        goto exit;
    }
    xor(myout, inctr, myout, sizeof(myout));
    if (!ak_ptr_is_equal_with_log(myout, outctr, sizeof(outctr))) {
        ak_error_message(ak_error_not_equal_data, __func__,
                         "the ctr mode encryption test from SM4 is wrong");
        result = ak_false;
        goto exit;
    }
    if ((error = ak_bckey_context_encrypt_ecb(&bkey, ivctr, myout, sizeof(ivctr))) !=
        ak_error_ok) {
        ak_error_message(error, __func__, "wrong ecb mode decryption of iv for ctr mode");
        result = ak_false;
        goto exit;
    }
    xor(myout, outctr, myout, sizeof(myout));
    if (!ak_ptr_is_equal_with_log(myout, inctr, sizeof(inctr))) {
        ak_error_message(ak_error_not_equal_data, __func__,
                         "the ctr mode decryption test from SM4 is wrong");
        result = ak_false;
        goto exit;
    }

    if (audit >= ak_log_maximum)
        ak_error_message(ak_error_ok, __func__,
                         "the ctr mode encryption/decryption test from SM4 is Ok");

    /* освобождаем ключ и выходим */
    exit:
    if ((error = ak_bckey_context_destroy(&bkey)) != ak_error_ok) {
        ak_error_message(error, __func__, "wrong destroying of secret key");
        return ak_false;
    }

    return result;
}

