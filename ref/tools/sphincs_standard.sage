# Set variables in the following three lines
tsec        = 128    # Pr[one attacker hash call works] <= 1/2^tsec
maxsigs     = 2^64   # at most 2^72
maxsigbytes = 64000  # Don't print parameters if signature size is larger
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


def compute_size_speed(h, d, b, k, w):
  # h = Height of the hypertree
  # d = number of layers in hypertree
  # b = height of a tree in FORS (log2(t))
  # k = number of trees in hypertree
  # w = winternitz parameter
  wots = wotschains(8*hashbytes,w)
  sigsize = ((b+1)*k+h+wots*d+1)*hashbytes
  speed   = k*2^(b+1) + d*(2^(h/d)*(wots*w+1))  # Rough speed estimate based on #hashes

  return sigsize, speed


param_sets = {
  "sphincs-128f": (66, 22, 6, 33, 16),
  "sphincs-128f-8 4 6 57 16 10": (8, 4, 6, 57, 16),
  "sphincs-192f": (66, 22, 8, 33, 16),
  "sphincs-256f": (68, 17, 9, 35, 16),
}

for param in param_sets:
  size, speed = compute_size_speed(*param_sets[param])
  print("%s: size=%s,speed=%s" % (param, size, speed))

