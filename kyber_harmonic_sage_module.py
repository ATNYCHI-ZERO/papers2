
# SageMath version of harmonic symbolic collapse for Kyber key recovery
R.<x> = PolynomialRing(ZZ)
q = 3329
n = 256

# Define the ciphertext space
C = [vector(ZZ, [randint(0, q) for _ in range(n)]) for _ in range(32)]

# Define symbolic FFT phase collapse operator
def collapse_operator(c):
    fft_vals = fft(c)
    phase = [arg(z) for z in fft_vals]
    return sum(sin(p) for p in phase)

collapse_signatures = [collapse_operator(c) for c in C]
deltas = [collapse_signatures[i+1] - collapse_signatures[i] for i in range(len(collapse_signatures)-1)]
matches = [i for i in range(len(deltas)) if abs(deltas[i]) < 0.1]

print("Resonant indices:", matches)
