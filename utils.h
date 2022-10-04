#ifndef utils_h
#define utils_h

void sha1_string_2_bytes(char *, unsigned char *);
void sha1_bytes_2_string(unsigned char *, char*);
int equals_arrays(unsigned char *, unsigned char *);

int dict_2_rainbowtable(char *);
void reduce(unsigned char *, char *, int);

int deriv_one(char *);

int breaker(char *);

#endif /* utils_h */
