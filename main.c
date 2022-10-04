
/*
PoC for a student project
Generate a rainbow table from a dictionary file
Use it to break sha1 hashed passwords

@Mk

Require to use a clean passwords dictionary
cat rockyou.txt | awk '{print $1}' > rockyou_clean.txt

gcc *.c -o rain -lssl -lcrypto
*/

#include "lib.h"
#include "utils.h"


int main(int argc, char** argv){

  int opt;

  // arg parsing
  while ((opt = getopt(argc, argv, "r:b:o"))!=-1){
    switch(opt){
      // create rainbowtable from dictionary
      case 'r':
        dict_2_rainbowtable(argv[optind-1]);
        break;
      // break
      case 'b':
        if(strlen(argv[optind-1])!=2*SHA_DIGEST_LENGTH){
          fprintf(stderr, "Error : wrong sha1 format\n");
          exit(1);
        }

        breaker(argv[optind-1]);
        break;
      // for testing purposes
      case 'o':
        deriv_one(argv[optind]);
        break;
      default:
        fprintf(stderr, "Usage: %s [-r|b] [file|hash]\n", argv[0]);
        exit(1);
    }
  }


  return 0;
}
