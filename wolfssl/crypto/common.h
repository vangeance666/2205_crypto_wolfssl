#ifndef common_h
#define common_h

#include <stdlib.h>
#include <ctype.h>

/**
* Checks if the strings are equal.
* @param  a           The first string.
* @param  b           The second string.
* @param  ignore_case Whether to ignore the case.
* @return             1 if the strings are equal, else 0.
*/
static int str_eq(const char *a, const char *b, int ignore_case) {

	if (a && b) {
		for (; *a && *b; ++a, ++b) {
			if (ignore_case ?
				toupper(*a) != toupper(*b) :
				*a != *b) return 0;
		}
		return *a == *b && *a == 0;
	}
	return 0;
}


/**
* Returns the index of the needle in the haystack.
* @param  needle      The needle string.
* @param  haystack    The haystack string.
* @param  ignore_case Whether to ignore the case.
* @return             The index of the needle if found, else -1.
*/
static int str_index(const char *needle, const char *haystack, int ignore_case) {

	const char *h = haystack, *p = needle;
	char c = 1;
	if (needle && haystack) {
		if (*h == *p && *p == 0) return 0;
		for (; c; c = *++h) {
			for (p = needle; *p && h[p - needle]; ++p) {
				if (ignore_case ?
					toupper(*p) != toupper(h[p - needle]) :
					*p != h[p - needle]) break;
			}
			if (!*p) return (int)(h - haystack);
		}
	}
	return -1;
}

static int is_digits(const char *s) {
	for (; *s; ++s) 
		if (!(*s >= '0' && *s <= '9'))
			return 0;
	 return 1;	
}


/**
* Converts hostname to ip address.
* For e.g www.google.com to 172.217.194.102
* Similar to how nslookup works
* @param  inName Pointer of hostname
* @param  outIp  Buffer to store IP Address
* @return        1 if success else 0
*/
static int host_to_ip(const char *inName, char *outIp) {

	WSADATA wsaData;
	struct hostent *remoteHost;
	struct in_addr **addrList;

	int suc, res; size_t i;

	StartTCP();

	if ((remoteHost = gethostbyname(inName)) == NULL) {
		fprintf(stderr, "[Error] Unabe to gethostname.\n", res);
		goto finish;
	}

	addrList = (struct in_addr **)remoteHost->h_addr_list;
	for (i = 0; addrList[i] != 0; ++i) {
		strcpy(outIp, inet_ntoa(*addrList[i]));
		suc = 1;
		break;
	}

finish:
	return suc;
}

int is_valid_ip(char *ip_str)
{
	int i, num, dots = 0;
	char *ptr;

	if (ip_str) {
		for (ptr = strtok(ip_str, "."); ptr; ) {
			/* after parsing string, it must contain only digits */
			if (!is_digits(ptr))
				return 0;

			num = atoi(ptr);

			/* check for valid IP */
			if (num >= 0 && num <= 255) {
				/* parse remaining string */
				ptr = strtok(NULL, ".");
				dots += (ptr != NULL);
			}
			else
				return 0;
		}
	}
	return (dots == 3);
}
/// To keep track if there is any malloc error.
static int safe_malloc_error = 0;

static void *safe_malloc(size_t n) {

	void *p = malloc(n);
	if (!p) {
		safe_malloc_error = 1;
	}
	return p;
}

/**
* Allocates memory for the string and copies the string.
* Do not forget to free the pointer when done!
* @param  s The string.
* @return   The copied string.
*/
static char *str_alloc_copy(const char *s) {

	const char *p;
	char *d = 0;
	if (s) {
		for (p = s; *p; ) ++p;
		d = (char *)safe_malloc(1 + p - s);
		if (d) {
			for (p = s; *p; ++p)
				d[p - s] = *p;
			d[p - s] = 0;
		}
		return d;
	}
	return 0;
}

static char *str_slice_copy(const char *s, int start, int end) {
	int length, i;
	char *d = 0;
	const char *p;
	if (s) {
		for (p = s; *p; ) ++p;
		length = end - start;
		if (length > 0 && length <= (p - s)) {
			d = (char *)safe_malloc(1 + length);
			if (d) {
				for (p = (s + start); *p && p < (s + end); ++p) {
					d[p - (s + start)] = *p;
				}
				d[length] = 0;
			}
			return d;
		}
	}
	return 0;
}

#endif


