#include <stdio.h>

#include <openssl/bn.h>

const char *p_hex = "C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7";
const char *q_hex = "F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F";

typedef struct _b12rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB12_RSA;

/* Make GCD */
BIGNUM* XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
    // gcd가 0일 때
    if (BN_is_zero(b))
    {
        BN_one(x); // x = 1
        BN_zero(y); // y = 0
        return BN_dup(a); // a를 복제한 값을 반환 (최대 공약수)
    }
    else if(BN_is_zero(a)){
        BN_one(y);
        BN_zero(x);
        return BN_dup(b);
    }

    /* 함수 내부에서 쓸 값 선언 */
    BIGNUM *tmp_x = BN_new();
    BN_copy(tmp_x,x);
    BIGNUM *tmp_y = BN_new();
    BN_copy(tmp_y,y);
    BIGNUM *tmp_a = BN_new();
    BN_copy(tmp_a,a);
    BIGNUM *tmp_b = BN_new();
    BN_copy(tmp_b,b);

    BIGNUM *gcd = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *r = BN_new();

    BIGNUM *s0 = BN_new();
    BIGNUM *s1 = BN_new();
    BN_zero(s1);
    BN_one(s0);
    BIGNUM *t0 = BN_new();
    BIGNUM *t1 = BN_new();
    BN_zero(t0);
    BN_one(t1);
    
    BIGNUM *tmp2 = BN_new();
    /* iteration을 높여가면서 반복 */
    while (!BN_is_zero(tmp_b))
    {
        /* a = q*b + r */
        BN_div(q,r,tmp_a,tmp_b,BN_CTX_new()); 
        BN_copy(tmp,tmp_a);
        BN_copy(tmp_a,tmp_b);
        BN_mul(tmp2,tmp_b,q,BN_CTX_new());
        BN_sub(tmp_b,tmp,tmp2);
        BN_copy(tmp,s0);
        BN_copy(s0,s1);
        BN_mul(tmp2,s1,q,BN_CTX_new());
        BN_sub(s1,tmp,tmp2);
        BN_copy(tmp,t0);
        BN_copy(t0,t1);
        BN_mul(tmp2,t1,q,BN_CTX_new());
        BN_sub(t1,tmp,tmp2);
    }

    BN_copy(gcd, tmp_a);
    BN_copy(x,s0);
    BN_copy(y,t0);

    BN_free(tmp_x);
    BN_free(tmp_y);
    BN_free(tmp_a);
    BN_free(tmp_b);
    BN_free(q);
    BN_free(r);
    BN_free(tmp2);
    BN_free(s0);
    BN_free(s1);
    BN_free(t0);
    BN_free(t1);
    

    return gcd;
}

/* Mod EXP generate */
int ExpMod(BIGNUM *r, const BIGNUM *base, const BIGNUM *exponent, BIGNUM *modulus) {
    BIGNUM *result = BN_new();
    BIGNUM *temp = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    if (!result || !temp || !ctx) {
        printf("Memory allocation error.\n");
        if (result) BN_free(result);
        if (temp) BN_free(temp);
        if (ctx) BN_CTX_free(ctx);
        return 0;
    }

    BN_one(result);
    // 지수가 0이 될때까지 반복 
    while (!BN_is_zero(exponent)) {
        // BN_mod_mul로 몫과 나머지를 구하기 
        if (BN_is_bit_set(exponent, 0)) { 
            if (!BN_mod_mul(temp, result, base, modulus, ctx)) {
                printf("error!\n");
                BN_free(result);
                BN_free(temp);
                BN_CTX_free(ctx);
                return 0;
            }
            BN_copy(result, temp);
        }

        if (!BN_mod_mul(temp, base, base, modulus, ctx)) {
            printf("error! \n");
            BN_free(result);
            BN_free(temp);
            BN_CTX_free(ctx);
            return 0;
        }

        BN_copy(base, temp);
        BN_rshift1(exponent, exponent);
    }
}

BOB12_RSA *BOB12_RSA_new(){ /* RSA 구조체 포인터 생성 */
    BOB12_RSA *ptr = malloc(sizeof(BOB12_RSA));
    return ptr;
}

int BOB12_RSA_free(BOB12_RSA *b12rsa){ /* RSA 구조체 포인터 해제 */
    free(b12rsa);
    return 1;
}

int BOB12_RSA_KeyGen(BOB12_RSA *b12rsa, int nBits){ /* RSA 구조체에 e,d,n 생성함수 */
    /*
        given p and q 
        N = p*q 
        e = (p-1)*(q-1)과 서로소 
        1 = ed%(p-1)(q-1)인 d를 찾는다 
    */
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *phi = BN_new(); /* phi = (p-1)*(q-1) */
    BIGNUM *gcd = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if (!BN_hex2bn(&p, p_hex)) {
        // Handle conversion error
        BN_free(p);
        return -1;
    }

    if (!BN_hex2bn(&q, q_hex)) {
        // Handle conversion error
        BN_free(q);
        return -1;
    }
    /* n = p*q */
    if(!BN_mul(n,p,q,BN_CTX_new())){
        return;
    }
    /* minus one each p and q to generate phi */
    if(!BN_sub(p,p,BN_value_one()) || !BN_sub(q,q,BN_value_one())){ 
        return;
    }
    
    BN_mul(phi,p,q,BN_CTX_new());
    /* ed = 1 (mod phi )*/
    /* phi -> Euler Totient */
    /* generate e -> prime which gurantee always coprime with phi(pq)=tmp */
    BN_generate_prime_ex(e,64,1,NULL,NULL,NULL);
    
    /* generate d which satisfy modulo inverse */
    
    gcd = XEuclid(x,y,e,phi);
    BN_copy(d,x);
    /* add member pointer to sturct */
    b12rsa->d = d;
    b12rsa->e = e;
    b12rsa->n = n;
    /* destruct */
    free(p);
    free(q);
    free(x);
    free(y);
    free(gcd);
    free(phi);
    return;
}

int BOB12_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB12_RSA *b12rsa){ /* 평문 서명 함수 */
    /* c = m^d mod n */
    ExpMod(c,m,b12rsa->d,b12rsa->n);
    return;
}

int BOB12_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB12_RSA *b12rsa){ /* 암호문 복호화 함수 */
    /* m = c^e mod n*/
    ExpMod(m,c,b12rsa->e,b12rsa->n);
    return;
}

void PrintUsage()
{
    printf("usage: rsa [-k | -e e n plaintext | -d d n ciphertext ]\n");
}

int main (int argc, char *argv[])
{
    BOB12_RSA *b12rsa = BOB12_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB12_RSA_KeyGen(b12rsa,1024);
        BN_print_fp(stdout,b12rsa->n);
        printf(" ");
        BN_print_fp(stdout,b12rsa->e);
        printf(" ");
        BN_print_fp(stdout,b12rsa->d);
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b12rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b12rsa->e, argv[2]);
            BOB12_RSA_Enc(out,in, b12rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b12rsa->d, argv[2]);
            BOB12_RSA_Dec(out,in, b12rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b12rsa!= NULL) BOB12_RSA_free(b12rsa);

    return 0;
}