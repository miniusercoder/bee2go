#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bee2/crypto/bels.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/brng.h>

static void generate(void *buf, size_t len, void *state)
{
    memset(buf, 0, len);
    brngCTRStepR(buf, len, state);
}

static void dump(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        printf("%02X", data[i]);
    putchar('\n');
}

int main(void)
{
    unsigned char common[32], member[32], shares[5 * 33];
    void *state = calloc(1, brngCTR_keep());
    if (!state)
        return 1;
    for (size_t len = 16; len <= 32; len += 8)
    {
        brngCTRStart(state, beltH() + 128, beltH() + 160);
        if (belsGenM0(common, len, generate, state) != ERR_OK)
            return 2;
        dump(common, len);
        if (belsStdM(common, len, 0) != ERR_OK)
            return 3;
        brngCTRStart(state, beltH() + 128, beltH() + 160);
        if (belsGenMi(member, len, common, generate, state) != ERR_OK)
            return 4;
        dump(member, len);
        if (belsShare3(shares, 5, 3, len, beltH()) != ERR_OK)
            return 5;
        dump(shares, 5 * (len + 1));
    }
    free(state);
    return 0;
}
