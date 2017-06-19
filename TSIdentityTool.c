/*
Copyright (c) 2017 landave

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// gcc TSIdentityTool.c -o TSIdentityTool -l tommath -l tomcrypt

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USE_LTM
#define LTM_DESC
#include <tomcrypt.h>

#define STD_BUF_SIZE 0x1000

#define min(a, b) (((a) < (b)) ? (a) : (b))

static const char *TSKEY = "b9dfaa7bee6ac57ac7b65f1094a1c155"
                           "e747327bc2fe5d51c512023fe54a2802"
                           "01004e90ad1daaae1075d53b7d571c30"
                           "e063b5a62a4a017bb394833aa0983e6e";

static void* safealloc(size_t len) {
  void* result = calloc(1, len);
  if (result == NULL) {
    printf("A memory allocation error occurred.\n");
    exit(-1);
  }
  
  return result;
}

static void safefree(void* ptr) {
  if (ptr != NULL) {
    free(ptr);
  }
}

static int obfuscateInplace(char *data, uint32_t length) {
  int dataSize = min(100, length);
  for (int i = 0; i < dataSize; i++) {
    data[i] ^= TSKEY[i];
  }

  char hash[20];
  hash_state ctx;
  if (sha1_init(&ctx) != CRYPT_OK)
    { return -1; }
  if (sha1_process(&ctx, (uint8_t*)data + 20, strlen(data + 20)) != CRYPT_OK)
    { return -1; }
  if (sha1_done(&ctx, (uint8_t*)hash) != CRYPT_OK)
    { return -1; }
  
  for (int i = 0; i < 20; i++) {
    data[i] ^= hash[i];
  }

  return 0;
}

static int deObfuscateInplace(char *data, uint32_t length) {
  char hash[20];
  hash_state ctx;
  if (sha1_init(&ctx) != CRYPT_OK)
    { return -1; }
  if (sha1_process(&ctx, (uint8_t*)data + 20, strlen(data + 20)) != CRYPT_OK)
    { return -1; }
  if (sha1_done(&ctx, (uint8_t*)hash) != CRYPT_OK)
    { return -1; }

  for (int i = 0; i < 20; i++) {
    data[i] ^= hash[i];
  }

  int dataSize = min(100, length);
  for (int i = 0; i < dataSize; i++) {
    data[i] ^= TSKEY[i];
  }
  return 0;
}

static int obfuscateKey(ecc_key* ecckey, char *out, size_t *outlen) {
  int ret = 0;
  char *clearbase64 = NULL;
  char *exportedkey = NULL;

  size_t exportedkeylen = STD_BUF_SIZE;
  exportedkey = (char*)safealloc(exportedkeylen);

  if (ecc_export((uint8_t*)exportedkey,
                 &exportedkeylen,
                 PK_PRIVATE /* we export the private (!) key */,
                 ecckey)
       != CRYPT_OK) {
    ret = -1;
    goto done;
  }


  size_t clearbase64len = STD_BUF_SIZE;
  clearbase64 = (char*)safealloc(clearbase64len);

  if (base64_encode((uint8_t*)exportedkey,
                    exportedkeylen,
                    (uint8_t*)clearbase64,
                    &clearbase64len)
      != CRYPT_OK) {
    ret = -1;
    goto done;
  }

  if (obfuscateInplace(clearbase64, clearbase64len)) {
    ret = -1;
    goto done;
  }

  char *obfuscatedKey = clearbase64;
  size_t obfuscatedKeylen = clearbase64len;

  if (base64_encode((uint8_t*)obfuscatedKey,
                    obfuscatedKeylen,
                    (uint8_t*)out,
                    outlen)
      != CRYPT_OK) {
    ret = -1;
    goto done;
  }

done:
  safefree(clearbase64);
  safefree(exportedkey);

  return ret;
}

static int deObfuscateKey(const char* obfuscatedIdentity_base64,
                          ecc_key* ecckey) {
  int ret = 0;

  char *actualIdentity = NULL;
  char *eccKeyString = NULL;

  size_t actualIdentitySize = STD_BUF_SIZE;
  actualIdentity = (char*)safealloc(actualIdentitySize);
  if (base64_decode((const uint8_t*)obfuscatedIdentity_base64,
                    strlen(obfuscatedIdentity_base64),
                    (uint8_t*)actualIdentity,
                    &actualIdentitySize)
       != CRYPT_OK) {
    ret = -1;
    goto done;
  }
  if (deObfuscateInplace(actualIdentity, actualIdentitySize)) {
    ret = -1;
    goto done;
  }

  long unsigned int eccKeyStringSize = STD_BUF_SIZE;
  eccKeyString = (char*)safealloc(eccKeyStringSize);
  if (base64_decode((uint8_t*)actualIdentity,
                    strlen(actualIdentity),
                    (uint8_t*)eccKeyString,
                    &eccKeyStringSize)
      != CRYPT_OK) {
    ret = -1;
    goto done;
  }

  if (ecc_import((uint8_t*)eccKeyString,
                 eccKeyStringSize,
                 ecckey)
      != CRYPT_OK)
    { ret = -1; }

done:
  safefree(actualIdentity);
  safefree(eccKeyString);

  return ret;
}

static int extractPublicKeyBase64(ecc_key* ecckey,
                                  char* out,
                                  long unsigned int *outlen) {
  int ret = 0;

  uint64_t ecc_public_asn1_size = STD_BUF_SIZE;
  char *ecc_public_asn1 = (char*)safealloc(ecc_public_asn1_size);
  if (ecc_export((uint8_t*)ecc_public_asn1,
                 &ecc_public_asn1_size,
                 PK_PUBLIC /* we export the public (!) key */,
                 ecckey)
       != CRYPT_OK) {
    ret = -1;
    goto done;
  }


  if (base64_encode((uint8_t*)ecc_public_asn1,
                    ecc_public_asn1_size,
                    (uint8_t*)out, outlen)
      != CRYPT_OK) {
    ret = -1;
    goto done;
  }

done:
  safefree(ecc_public_asn1);

  return ret;
}

static int parseIni(const char* filename,
                    char* out_identity,
                    size_t out_identity_len,
                    uint64_t *out_counter) {
  int ret = 0;

  FILE *fp = fopen(filename, "r");
  if (fp == NULL) {
    return -1;
  }

  char *filecontent = (char*)safealloc(STD_BUF_SIZE + 1);
  size_t newLen = fread(filecontent, sizeof(char), STD_BUF_SIZE, fp);
  if (newLen == 0) {
    printf("Error reading file.\n");
    ret = -1;
    goto done;
  }
  filecontent[++newLen] = '\0';

  const char *IDENT_STR = "identity";
  const char *currentpos = strstr(filecontent, IDENT_STR);
  if (currentpos == NULL) { ret = -1; goto done; }

  currentpos = (const char *)memchr(currentpos, '"', strlen(currentpos));
  if (currentpos == NULL) { ret = -1; goto done; }

  const char *counteridentity_startpos = currentpos + 1;
  const char *counteridentity_endpos = memchr(currentpos + 1,
                                              '"',
                                              strlen(currentpos + 1));
  if (counteridentity_endpos == NULL) { ret = -1; goto done; }
  const char *counterptr = counteridentity_startpos;

  const char *delimiter_pos = memchr(counteridentity_startpos,
                                     'V',
                                     strlen(counteridentity_startpos));
  if (delimiter_pos == NULL || delimiter_pos >= counteridentity_endpos)
    { ret = -1; goto done; }

  const char *identityptr = delimiter_pos + 1;

  size_t counter_len = delimiter_pos - counterptr;
  size_t identity_len = counteridentity_endpos - delimiter_pos - 1;
  if (identity_len > out_identity_len) { ret = -1; goto done; }

  // sanity checking counter
  for (size_t i = 0; i < counter_len; i++) {
    if (counterptr[i] < '0' || counterptr[i] > '9')
      { ret = -1; goto done; }
  }

  // sanity checking identity
  for (size_t i = 0; i < identity_len; i++) {
    if (!isprint(identityptr[i]) && !isspace(identityptr[i]))
      { ret = -1; goto done; }
  }

  strncpy(out_identity, identityptr, identity_len);
  *out_counter = strtoull(counterptr, NULL, 10);

done:
  fclose(fp);
  safefree(filecontent);

  return ret;
}

static int getIDFingerprint(const char* publickey,
                             char* out, 
                             long unsigned int *outlen) {
  char hash[20];
  hash_state ctx;
  if (sha1_init(&ctx) != CRYPT_OK) {
    return 1;
  }
  if (sha1_process(&ctx,
                   (const uint8_t*)publickey,
                   strlen(publickey))
      != CRYPT_OK) {
    return 1;
  }
  if (sha1_done(&ctx, (uint8_t*)hash) != CRYPT_OK) {
    return 1;
  }
 
  if (base64_encode((uint8_t*)hash,
                    sizeof(hash)/sizeof(hash[0]),
                    (uint8_t*)out, outlen)
      != CRYPT_OK) {
    return 1; 
  }
  
  return 0;
}

static uint8_t getSecurityLevel(const char* publickey, uint64_t counter) {
  size_t publickey_len = strlen(publickey);
  // a uint64_t takes at most 20 decimal digits
  size_t hashinput_len = publickey_len + 20 + 1;

  char* hashinput = (char*)safealloc(hashinput_len);
  size_t zerobytes = 0;
  size_t zerobits = 0;

  strncpy(hashinput, publickey, hashinput_len);
  int counter_len = snprintf(hashinput + publickey_len,
                              hashinput_len-publickey_len,
                              "%" PRIu64, counter);
  if (counter_len <= 0) { goto done; }

  char hash[20];
  hash_state ctx;
  if (sha1_init(&ctx) != CRYPT_OK) { goto done; }
  if (sha1_process(&ctx,
                   (uint8_t*)hashinput,
                   publickey_len + (size_t)counter_len)
      != CRYPT_OK) { goto done; }
  if (sha1_done(&ctx, (uint8_t*)hash) != CRYPT_OK) { goto done; }

  zerobytes = 0;
  while (zerobytes < 20 && hash[zerobytes] == 0) {
    zerobytes++;
  }
  zerobits = 0;
  if (zerobytes < 20) {
    uint8_t lastbyte = hash[zerobytes];
    while (!(lastbyte & 1)) {
      zerobits++;
      lastbyte >>= 1;
    }
  }

done:
  safefree(hashinput);

  return 8 * zerobytes + zerobits;
}

static void generateKey(const char *nickname, const char *outfile, bool good) {
  ecc_key *ecckey = NULL;
  char *obfuscatedKey = NULL;
  char *publickey = NULL;
  char *idfingerprint = NULL;
  
  FILE *file = fopen(outfile, "w");

  if (file == NULL) {
    printf("Error: The output ini file is not writable.\n");
    goto done;
  }
  
  if (good) {
    printf("Generating a good identity. This can take while...\n");
  }
  
  // this is the standard NIST ECC-256 curve
  // used by TeamSpeak
  int idx = 5;

  if (!ltc_ecc_is_valid_idx(idx)) {
    printf("Error. Curve index is invalid.\n");
    goto done;
  }

  ecckey = (ecc_key*)safealloc(sizeof(ecc_key));

  obfuscatedKey = (char*)safealloc(STD_BUF_SIZE);
  publickey = (char*)safealloc(STD_BUF_SIZE);

  prng_state prng;
  if (register_prng(&yarrow_desc) == -1) {
    goto done;
  }

  int err = rng_make_prng(1024, find_prng("yarrow"), &prng, NULL);
  if (err != CRYPT_OK) {
    printf("Error setting up PRNG, %s\n", error_to_string(err));
    goto done;
  }
  
  size_t publickeylen;
  do {
    if (ecc_make_key_ex(&prng,
                        find_prng("yarrow"),
                        ecckey,
                        &ltc_ecc_sets[idx])) {
      printf("An error occurred while generating the key.\n");
      goto done;
    }

    size_t obfuscatedKeylen = STD_BUF_SIZE;
    if (obfuscateKey(ecckey, obfuscatedKey, &obfuscatedKeylen)) {
      printf("An error occurred while obfuscating the key.\n");
      goto done;
    }

    publickeylen = STD_BUF_SIZE;
    if (extractPublicKeyBase64(ecckey, publickey, &publickeylen)) {
      printf("An error occurred while exporting the public key.\n");
      goto done;
    }
  } while (good && publickeylen > 100);
  
  uint64_t counter = 0;
  while (getSecurityLevel(publickey, counter) < 8) { counter++; }
  
  long unsigned int idfingerprintlength = STD_BUF_SIZE;
  idfingerprint = (char*)safealloc(idfingerprintlength);
  
  if (getIDFingerprint(publickey,
                      idfingerprint,
                      &idfingerprintlength)) {
    printf("An error occurred while generating "
       "the fingerprint of the identity.\n");
    goto done;
  }

  printf("Public key: %s\n", publickey);
  printf("Public key length (Base64): %zd\n", publickeylen);
  printf("Fingerprint: %s\n", idfingerprint);
  printf("Current security level: %u (with counter=%" PRIu64 ")\n",
          getSecurityLevel(publickey, counter), counter);

  printf("Obfuscated key pair: %s\n", obfuscatedKey);
  char counterstr[20];
  snprintf(counterstr, sizeof(counterstr), "%" PRIu64, counter);

  printf("Curve name: %s (NIST)\n", ecckey->dp->name);
  printf("Curve size (octets): %d\n", ecckey->dp->size);
  
  int writeres = fprintf(file, "[Identity]\n" "id=%s\n"
                "identity=\"%sV%s\"\n"
                "nickname=%s\n"
                "phonetic_nickname=\n",
                nickname, counterstr, obfuscatedKey, nickname);
          
  if (writeres < 0) {
    printf("Output ini file could not be written.\n");
  } else {
    printf("Identity has been saved.\n");
  }
  

done:
  fclose(file);
  safefree(ecckey);
  safefree(obfuscatedKey);
  safefree(publickey);
  safefree(idfingerprint);
}

static void readIdentity(char* filename) {
  char* obfuscatedIdentity_base64 = (char*)safealloc(STD_BUF_SIZE);
  uint64_t counter;
  
  if (access(filename, F_OK) != 0) {
    printf("Error: The ini file does not exist.\n");
    exit(1);
  }
  
  if (access(filename, R_OK) != 0) {
    printf("Error: The ini file is not readable.\n");
    exit(1);
  }
  
  if (parseIni(filename,
               obfuscatedIdentity_base64,
               STD_BUF_SIZE, &counter)) {
    printf("An error occurred while parsing the ini file.\n");
    exit(1);
  }

  ecc_key *ecckey = (ecc_key*)safealloc(sizeof(ecc_key));
  if (deObfuscateKey(obfuscatedIdentity_base64, ecckey)) {
    printf("An error occurred while deobfuscating the identity.\n");
    exit(1);
  }

  uint64_t ecc_public_base64_size = STD_BUF_SIZE;
  char *ecc_public_base64 = (char*)safealloc(ecc_public_base64_size);
  
  if (extractPublicKeyBase64(ecckey,
                              ecc_public_base64,
                              &ecc_public_base64_size)) {
    printf("An error occurred while processing "
       "the obfuscated identity string.\n");
    exit(1);
  }
  
  long unsigned int idfingerprintlength = STD_BUF_SIZE;
  char *idfingerprint = (char*)safealloc(idfingerprintlength);
  
  if (getIDFingerprint(ecc_public_base64,
                      idfingerprint,
                      &idfingerprintlength)) {
    printf("An error occurred while generating "
       "the fingerprint of the identity.\n");
    exit(1);
  }

  printf("Public key: %s\n", ecc_public_base64);
  printf("Public key length (Base64): %zd\n", strlen(ecc_public_base64));
  printf("Fingerprint: %s\n", idfingerprint);
  printf("Curve name: %s%s\n", ecckey->dp->name,
           (ecckey->idx >= 0 ? " (NIST)" : ""));
  printf("Curve size (octets): %d\n", ecckey->dp->size);
  printf("Current security level: %u (with counter=%" PRIu64 ")\n",
           getSecurityLevel(ecc_public_base64, counter), counter);


  safefree(ecc_public_base64);
  safefree(obfuscatedIdentity_base64);
  safefree(ecckey);
  safefree(idfingerprint);
}

static void printhelp(void) {
  printf("Usage: TSIdentityTool COMMAND [OPTIONS]\n\n");
  printf("Available commands:\n");
  printf("read inidentity.ini\n");
  printf("generate nickname outidentity.ini\n");
  printf("generategood nickname outidentity.ini\n");
}

static bool safestrequal(const char *s1, const char *s2) {
  const size_t strlen1 = strlen(s1);
  const size_t strlen2 = strlen(s2);
  return strlen1==strlen2 && strncmp(s1, s2, strlen1) == 0;
}

int main(int argc, char* argv[]) {
  // initialize math context for libtomcat, using libtommath
  ltc_mp = ltm_desc;

  if (argc < 2) {
    printhelp();
    exit(1);
  }

  if (safestrequal(argv[1],"read")) {
    if (argc < 3) {
      printf("Missing argument: input ini identity file.\n");
    } else {
      readIdentity(argv[2]);
    }
  } else if (safestrequal(argv[1],"generate")) {
    if (argc < 3) {
      printf("Missing argument: identity nickname.\n");
    } else if (argc < 4) {
      printf("Missing argument: output ini identity file.\n");
    } else {
      generateKey(argv[2], argv[3], false);
    }
  } else if (safestrequal(argv[1],"generategood")) {
    if (argc < 3) {
      printf("Missing argument: identity nickname.\n");
    } else if (argc < 4) {
      printf("Missing argument: output ini identity file.\n");
    } else {
      generateKey(argv[2], argv[3], true);
    }
  } else {
    printhelp();
    exit(1);
  }

  return 0;
}
