#pragma once
#ifndef argparse_h
#define argparse_h
int   myoptind;
char *myoptarg;

/**
*
* @param argc Number of argv strings
* @param argv Array of string arguments
* @param optstring String containing the supported alphanumeric arguments.
*                  A ':' following a character means that it requires a
*                  value in myoptarg to be set. A ';' means that the
*                  myoptarg is optional. myoptarg is set to "" if not
*                  present.
* @return Option letter in argument
*/
static int mygetopt(int argc, char **argv, const char *optstring)
{
	static char* next = NULL;

	char  c;
	char* cp;

	/* Added sanity check becuase scan-build complains argv[myoptind] access
	* results in a null pointer dereference. */
	if (argv == NULL) {
		myoptarg = NULL;
		return -1;
	}

	if (myoptind == 0)
		next = NULL;   /* we're starting new/over */

	if (next == NULL || *next == '\0') {
		if (myoptind == 0)
			myoptind++;

		if (myoptind >= argc || argv[myoptind] == NULL ||
			argv[myoptind][0] != '-' || argv[myoptind][1] == '\0') {
			myoptarg = NULL;
			if (myoptind < argc)
				myoptarg = argv[myoptind];

			return -1;
		}

		if (strcmp(argv[myoptind], "--") == 0) {
			myoptind++;
			myoptarg = NULL;

			if (myoptind < argc)
				myoptarg = argv[myoptind];

			return -1;
		}

		next = argv[myoptind];
		next++;                  /* skip - */
		myoptind++;
	}

	c = *next++;
	/* The C++ strchr can return a different value */
	cp = (char*)strchr(optstring, c);

	if (cp == NULL || c == ':' || c == ';')
		return '?';

	cp++;

	if (*cp == ':') {
		if (*next != '\0') {
			myoptarg = next;
			next = NULL;
		}
		else if (myoptind < argc) {
			myoptarg = argv[myoptind];
			myoptind++;
		}
		else
			return '?';
	}
	else if (*cp == ';') {
		myoptarg = (char*)"";
		if (*next != '\0') {
			myoptarg = next;
			next = NULL;
		}
		else if (myoptind < argc) {
			/* Check if next argument is not a parameter argument */
			if (argv[myoptind] && argv[myoptind][0] != '-') {
				myoptarg = argv[myoptind];
				myoptind++;
			}
		}
	}

	return c;
}

#endif