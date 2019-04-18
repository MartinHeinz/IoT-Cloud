import numpy as np
import matplotlib.pyplot as plt

import mmh3


def bsd_rand(seed):
    def rand():
        nonlocal seed
        seed = (1103515245 * seed + 12345) & 0x7fffffff
        return seed
    return rand


def hash_knuth(i):
    return i * 2654435761 % 2 ^ 32


# Create data
N = 10000
SEED = 42

# x = [bsd_rand(i)() for i in range(N)]
# x = [hash_knuth(i) for i in range(N)]
x = [mmh3.hash(str(i), SEED) for i in range(N)]
y = list(range(N))

area = np.pi * 2

# Plot
plt.subplot(121)
plt.scatter(x, y, s=area, c=x, alpha=0.5)
plt.title('Randomness of hash functions.')
plt.xlabel('x')
plt.ylabel('y')
plt.subplot(122)
plt.hist(x, bins=100)
plt.show()
