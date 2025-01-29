# https://www.secg.org/SEC2-Ver-1.0.pdf
# VERY BAD CODE DO NOT USE (For one thing, I wrote this years ago)

# Section 2.7.1 - Curve Parameters

# the modulus of the prime field
p = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F

# curve parameters
a = 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000
b = 0x00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000007

# the base point
Gx = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798
Gy = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8

# the order of the field
n = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
h = 1  # cofactor


class Point:
	x: int
	y: int
	is_infinity: bool

	def __init__(self, x: int, y: int, is_infinity: bool=False):
		# TODO verify is on curve
		self.x = x
		self.y = y
		self.is_infinity = is_infinity

	def __repr__(self):
		if self.is_infinity:
			return "<Point(curve=secp256k1, Infinity)>"
		else:
			return f"<Point(curve=secp256k1, x={self.x:x}, y={self.y:x})>"

	def __copy__(self):
		return Point(self.x, self.y, self.is_infinity)

	def __eq__(self, other):
		if other.is_infinity:
			return self.is_infinity
		if self.is_infinity:
			return False
		return self.x == other.x and self.y == other.y

	# point negation
	def __neg__(self):
		if self.is_infinity:
			return self.__copy__()
		result = self.__copy__()
		result.y = (-self.y) % p
		return result

	# point addition
	# https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
	# TODO: implement __iadd__ (in-place add)
	def __add__(self, other):
		P = self
		Q = other
		if P == Infinity:
			return Q
		if Q == Infinity:
			return P
		if P.x == Q.x and P.y == -Q.y:
			return Infinity.__copy__()
		if P == Q:  # point doubling
			tmp = ((3 * pow(P.x, 2, p) + a) * pow(2 * P.y, -1, p)) % p
		else:
			tmp = ((Q.y - P.y) * pow(Q.x - P.x, -1, p)) % p
		x3 = (pow(tmp, 2, p) - P.x - Q.x) % p
		y3 = (tmp * (P.x - x3) - P.y) % p
		return Point(x3, y3)

	# scalar multiplication via double-and-add
	def scalar_mul(self, n):
		assert type(n) is int
		Q = self
		R = Infinity.__copy__()
		while n:
			if n % 2:
				R += Q
			Q += Q
			n >>= 1
		return R

	def xy(self):
		return self.x, self.y


Infinity = Point(None, None, True)
G = Point(Gx, Gy)
