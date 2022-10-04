#include "utils.h"
#include "lib.h"

//SHA_DIGEST_LENGTH == 20

#define SIZE 8 // reduced password size
#define FIRST_CHAR 0x21
#define LAST_CHAR 0x7E


// copy an hex string sha1 into a correponding byte array
void sha1_string_2_bytes( char * sha, unsigned char * sha_bytes ){
    for ( int i = 0 ; i < SHA_DIGEST_LENGTH ; i++ )
        sscanf( &sha[2 * i], "%2hhx", &sha_bytes[i] ) ;
}

// print sha1 bytes to a string
void sha1_bytes_2_string(unsigned char * sha_bytes, char *sha){
  for( int i = 0 ; i < SHA_DIGEST_LENGTH ; i++ )
    sha += sprintf(sha, "%02x", sha_bytes[i]);
}

// compare two byte arrays for equality
int equals_arrays( unsigned char * a, unsigned char * b ){
    for ( int i = 0 ; i < SHA_DIGEST_LENGTH ; i++)
        if( a[i] != b[i] )
            return 0 ;
    return 1 ;
}

// reduce a hash into a string
void reduce(unsigned char *hash, char *reduced, int pos){
    for(int c = 0 ; c < SIZE ; c++)
      reduced[c] = FIRST_CHAR + (hash[pos+c] % (LAST_CHAR-FIRST_CHAR+1));
    reduced[SIZE] = '\0';
}


// read password candidates from file one per line
// compute sha1 and reduce it three times
int dict_2_rainbowtable(char *file_dict){

  FILE *fi, *fo;
  char *line=NULL;
  size_t len;
  ssize_t read_size;

  unsigned char hash_bytes[SHA_DIGEST_LENGTH] = {0} ;
  char hash[2 * SHA_DIGEST_LENGTH]={0};
  char reduced[10] = {0};

  fi=fopen(file_dict,"r");
  if(fi==NULL){
    fprintf(stderr, "Error: opening %s\n", file_dict);
    exit(1);
  }

  fo=fopen("rainbow.txt", "w");
  if(fo==NULL){
    fprintf(stderr, "Error: creating file\n");
    exit(1);
  }

  // read file line by line
  while((read_size=getline(&line, &len, fi)) != -1 ){
    // remove CRLF
    line[read_size-1]='\0';
    SHA1(line, read_size-1, hash_bytes);

    sha1_bytes_2_string(hash_bytes,hash);

    for(int i=0; i<3; i++){
      reduce(hash_bytes, reduced, i);
      SHA1(reduced, SIZE, hash_bytes);
    }
    sha1_bytes_2_string(hash_bytes,hash);
    fprintf(fo, "%s %s\n", line, hash);
  }

  fclose(fi);
  fi=NULL;
  fclose(fo);
  fo=NULL;

  return 0;
}

// deriv just one password for testing purposes
int deriv_one(char *pass){

  unsigned char hash_bytes[SHA_DIGEST_LENGTH] = {0} ;
  char hash[2 * SHA_DIGEST_LENGTH]={0};
  char reduced[10] = {0};
  int len;

  len=strlen(pass);

  SHA1(pass, len, hash_bytes);
  sha1_bytes_2_string(hash_bytes,hash);
  printf("%s %s\n",pass, hash);

  for(int i=0; i<3; i++){
    reduce(hash_bytes, reduced, i);
    SHA1(reduced, SIZE, hash_bytes);
    sha1_bytes_2_string(hash_bytes,hash);
    printf("%s %s\n",reduced, hash);
  }
  return 0;
}

// search in rainbow.txt if hash is known
// pass -> hash(pass) -> reduce_1 -> hash(reduced_1) -> reduce_2 -> hash(reduced_2) -> reduce_3 -> hash(reduced_3) == final_hash
int breaker(char *target){

  // rainbow.txt
  FILE *fi;

  // hash to crack
  unsigned char target_bytes[SHA_DIGEST_LENGTH] = {0} ;

  // tmp
  unsigned char hash_bytes[SHA_DIGEST_LENGTH] = {0} ;
  char hash[2 * SHA_DIGEST_LENGTH]={0};
  char reduced_1[10] = {0};
  char reduced_2[10] = {0};
  char reduced_3[10] = {0};
  int found = 0;

  // read line by line
  char *line=NULL;
  size_t len;
  ssize_t read_size;
  char *pass;
  char *final_hash;
  unsigned char final_hash_bytes[SHA_DIGEST_LENGTH] = {0} ;
  char delim[]=" \n";
  int len_pass;

  if((fi=fopen("rainbow.txt", "r"))==NULL){
    printf("Error opening rainbow.txt\n");
    exit(1);
  }

  sha1_string_2_bytes(target, target_bytes);

  while((read_size=getline(&line, &len, fi)) != -1 ){
    pass=strtok(line, delim);
    final_hash=strtok(NULL, delim);

    // trick in case of malformed input in rainbow.txt
    if(final_hash==NULL)
      final_hash=pass;

    final_hash[2*SHA_DIGEST_LENGTH]='\0';
    len_pass=strlen(pass);


    // target is last hash, ie reduce_3 password
    sha1_string_2_bytes(final_hash, final_hash_bytes);

    if(equals_arrays(target_bytes, final_hash_bytes)){

      SHA1(pass, len_pass, hash_bytes);
      reduce(hash_bytes, reduced_1, 0);
      SHA1(reduced_1, SIZE, hash_bytes);
      reduce(hash_bytes, reduced_2, 1);
      SHA1(reduced_2, SIZE, hash_bytes);
      reduce(hash_bytes, reduced_3, 2);
      printf("Pass found : %s\n",reduced_3);
      found=1;
      break;
    }

    // target is hash of reduce_2
    sha1_string_2_bytes(target, hash_bytes);
    reduce(hash_bytes, reduced_3, 2);
    SHA1(reduced_3, SIZE, hash_bytes);

    if(equals_arrays(final_hash_bytes, hash_bytes)){

      SHA1(pass, len_pass, hash_bytes);
      reduce(hash_bytes, reduced_1, 0);
      SHA1(reduced_1, SIZE, hash_bytes);
      reduce(hash_bytes, reduced_2, 1);
      printf("Pass found : %s\n",reduced_2);
      found=1;
      break;
    }

    // target is hash of reduce_1
    sha1_string_2_bytes(target, hash_bytes);
    reduce(hash_bytes, reduced_2, 1);
    SHA1(reduced_2, SIZE, hash_bytes);
    reduce(hash_bytes, reduced_3, 2);
    SHA1(reduced_3, SIZE, hash_bytes);

    if(equals_arrays(final_hash_bytes, hash_bytes)){

      SHA1(pass, len_pass, hash_bytes);
      reduce(hash_bytes, reduced_1, 0);
      printf("Pass found : %s\n",reduced_1);
      found=1;
      break;
    }

    // target is hash of password
    SHA1(pass, len_pass, hash_bytes);

    if(equals_arrays(target_bytes, hash_bytes)){
      printf("Pass found : %s\n",pass);
      found=1;
      break;
    }

  }

  if(!found)
    printf("Pass not found\n");
  fclose(fi);
  fi=NULL;
  return 0;
}
