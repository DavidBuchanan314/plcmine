#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <time.h>

static const uint8_t B64_CHARSET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void bytes_to_b64_string_nopad(uint8_t *resbuf, const uint8_t *data, size_t data_len)
{
	/* XXX: assumes resbuf is big enough! */
	uint8_t a, b, c;
	size_t data_i = 0;
	while ( data_i + 2 < data_len) {
		a = data[data_i++];
		b = data[data_i++];
		c = data[data_i++];
		*resbuf++ = B64_CHARSET[(           (a >> 2)) & 0x3f];
		*resbuf++ = B64_CHARSET[((a << 4) | (b >> 4)) & 0x3f];
		*resbuf++ = B64_CHARSET[((b << 2) | (c >> 6)) & 0x3f];
		*resbuf++ = B64_CHARSET[((c << 0)           ) & 0x3f];
	}
	switch (data_len - data_i)
	{
	case 2:
		a = data[data_i++];
		b = data[data_i++];
		*resbuf++ = B64_CHARSET[(           (a >> 2)) & 0x3f];
		*resbuf++ = B64_CHARSET[((a << 4) | (b >> 4)) & 0x3f];
		*resbuf++ = B64_CHARSET[((b << 2)           ) & 0x3f];
		break;
	case 1:
		a = data[data_i++];
		*resbuf++ = B64_CHARSET[(           (a >> 2)) & 0x3f];
		*resbuf++ = B64_CHARSET[((a << 4)           ) & 0x3f];
		break;
	case 0:
		// nothing to do here
		break;
	default:
		assert(0); // unreachable
	}
}

static const uint8_t B32_CHARSET[] = "abcdefghijklmnopqrstuvwxyz234567";

static void bytes_to_b32_multibase(uint8_t *resbuf, const uint8_t *data, size_t data_len)
{
	/* XXX: assumes resbuf is big enough! */
	uint8_t a, b, c, d, e;
	size_t data_i = 0;
	while ( data_i + 4 < data_len) {
		a = data[data_i++];
		b = data[data_i++];
		c = data[data_i++];
		d = data[data_i++];
		e = data[data_i++];
		// 76543 21076 54321 07654 32107 65432 10765 43210
		// aaaaa aaabb bbbbb bcccc ccccd ddddd ddeee eeeee
		// 43210 43210 43210 43210 43210 43210 43210 43210
		*resbuf++ = B32_CHARSET[(           (a >> 3)) & 0x1f];
		*resbuf++ = B32_CHARSET[((a << 2) | (b >> 6)) & 0x1f];
		*resbuf++ = B32_CHARSET[(           (b >> 1)) & 0x1f];
		*resbuf++ = B32_CHARSET[((b << 4) | (c >> 4)) & 0x1f];
		*resbuf++ = B32_CHARSET[((c << 1) | (d >> 7)) & 0x1f];
		*resbuf++ = B32_CHARSET[(           (d >> 2)) & 0x1f];
		*resbuf++ = B32_CHARSET[((d << 3) | (e >> 5)) & 0x1f];
		*resbuf++ = B32_CHARSET[((e << 0)           ) & 0x1f];
	}
	switch (data_len - data_i) // TODO: can this be simplified, with fallrthu perhaps?
	{
	case 4:
		a = data[data_i++];
		b = data[data_i++];
		c = data[data_i++];
		d = data[data_i++];
		*resbuf++ = B32_CHARSET[(           (a >> 3)) & 0x1f];
		*resbuf++ = B32_CHARSET[((a << 2) | (b >> 6)) & 0x1f];
		*resbuf++ = B32_CHARSET[(           (b >> 1)) & 0x1f];
		*resbuf++ = B32_CHARSET[((b << 4) | (c >> 4)) & 0x1f];
		*resbuf++ = B32_CHARSET[((c << 1) | (d >> 7)) & 0x1f];
		*resbuf++ = B32_CHARSET[(           (d >> 2)) & 0x1f];
		*resbuf++ = B32_CHARSET[((d << 3)           ) & 0x1f];
		break;
	case 3:
		a = data[data_i++];
		b = data[data_i++];
		c = data[data_i++];
		*resbuf++ = B32_CHARSET[(           (a >> 3)) & 0x1f];
		*resbuf++ = B32_CHARSET[((a << 2) | (b >> 6)) & 0x1f];
		*resbuf++ = B32_CHARSET[(           (b >> 1)) & 0x1f];
		*resbuf++ = B32_CHARSET[((b << 4) | (c >> 4)) & 0x1f];
		*resbuf++ = B32_CHARSET[((c << 1)           ) & 0x1f];
		break;
	case 2:
		a = data[data_i++];
		b = data[data_i++];
		*resbuf++ = B32_CHARSET[(           (a >> 3)) & 0x1f];
		*resbuf++ = B32_CHARSET[((a << 2) | (b >> 6)) & 0x1f];
		*resbuf++ = B32_CHARSET[(           (b >> 1)) & 0x1f];
		*resbuf++ = B32_CHARSET[((b << 4)           ) & 0x1f];
		break;
	case 1:
		a = data[data_i++];
		*resbuf++ = B32_CHARSET[(           (a >> 3)) & 0x1f];
		*resbuf++ = B32_CHARSET[((a << 2)           ) & 0x1f];
		break;
	case 0:
		// nothing to do here
		break;
	default:
		assert(0); // unreachable
	}
}

double get_current_timestamp(void) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}
