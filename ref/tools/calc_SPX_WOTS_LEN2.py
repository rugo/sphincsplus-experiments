import math

SPX_N = 16

SPX_WOTS_W = 4
spx_log = int(math.log2(SPX_WOTS_W))

LEN1 = 8 * SPX_N // spx_log

LEN2 = math.floor(math.log2((LEN1 * (SPX_WOTS_W - 1))) / math.log2(SPX_WOTS_W)) + 1

print(LEN2)