# Set variables in the following three lines
tsec        = 128    # Pr[one attacker hash call works] <= 1/2^tsec
maxsigs     = 2^10   # at most 2^72
maxsigbytes = 30000  # Don't print parameters if signature size is larger
#### Don't edit below this line ####

#### Generic caching layer to save time

import collections
class memoized(object):
  def __init__(self,func):
    self.func = func
    self.cache = {}
    self.__name__ = 'memoized:' + func.__name__
  def __call__(self,*args):
    if not isinstance(args,collections.Hashable):
      return self.func(*args)
    if not args in self.cache:
      self.cache[args] = self.func(*args)
    return self.cache[args]

#### SPHINCS+ analysis

F = RealIntervalField(tsec+100)
sigmalimit = F(2^(-tsec))
donelimit  = 1-sigmalimit/2^20
hashbytes  = tsec/8 # length of hashes in bytes

# Pr[exactly r sigs hit the leaf targeted by this forgery attempt]
@memoized
def qhitprob(leaves,qs,r):
    p = 1/F(leaves)
    return binomial(qs,r)*p^r*(1-p)^(qs-r)

# Pr[FORS forgery given that exactly r sigs hit the leaf] = (1-(1-1/F(2^b))^r)^k
@memoized
def forgeryprob(b,r,k):
    if k == 1: return 1-(1-1/F(2^b))^r
    return forgeryprob(b,r,1)*forgeryprob(b,r,k-1)

# Number of WOTS chains
@memoized
def wotschains(m,w):
    la = ceil(m / log(w,2))
    return la + floor(log(la*(w-1), 2) / log(w,2)) + 1

s = log(maxsigs,2)
for h in range(s-8,s+20):                                             # Iterate over total tree height
    leaves = 2^h
    for b in range(3,24):                                             # Iterate over height of FORS trees
        for k in range(1,128):                                         # Iterate over number of FORS trees
            sigma = 0
            r = 1
            done = qhitprob(leaves,maxsigs,0)
            while done < donelimit:
                t = qhitprob(leaves,maxsigs,r)
                sigma += t*forgeryprob(b,r,k)
                if sigma > sigmalimit: break
                done  += t
                r     += 1
            sigma += min(0,1-done)
            if sigma > sigmalimit: continue
            sec = ceil(log(sigma,2))
            for d in range(4,h):                                      # Iterate over number of sub-trees
                if h % d == 0 and h <= 64+(h/d):
                    for w in [4, 16, 256]:                                # Try different Winternitz parameters
                        wots = wotschains(8*hashbytes,w)
                        sigsize = ((b+1)*k+h+wots*d+1)*hashbytes
                        speed   = k*2^(b+1) + d*(2^(h/d)*(wots*w+1))  # Rough speed estimate based on #hashes
                        keygen_hashes = 2^(h/d) * (wots * w + wots + 2) - 1
                        sign_hashes = d * (2^(h/d) * (wots * w + wots + 2) -1 ) + k * (3*2^b - 1)
                        if sigsize < maxsigbytes and -sec < 2*tsec:
                           # Output scheme. 
                           # Fields are:
                           # - Signature Size
                           # - Estimated speed based on #hashes
                           # - #Hashes during Verification (omitted)
                           # - generic bit security for quantum algorithms
                           # - Height of hyptertree
                           # - Layers in hypertree
                           # - Height of FORS tree
                           # - Number of FORS trees per hyptertree leaf
                           # - Winternitz parameter
                           # - Security degredation parameter (omitted)
                           # - Number of hash function calls for keygen
                           # - Number of hash function calls for signing
                           # The ommitted values are set to 0, but are included anyways to keep 
                           # compatibility to the format used in https://eprint.iacr.org/2022/1725
                           print("\t".join(map(str, (sigsize, speed, 0, sec, h,d,b,k,w, 0, keygen_hashes, sign_hashes))))
