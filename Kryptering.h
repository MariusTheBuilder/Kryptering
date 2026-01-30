#ifndef KRYPTERING_H
#define KRYPTERING_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

// Diffie-Hellman konstanter.
#define PRIME_MODULUS 2147483647ULL 
#define GENERATOR 7

#define TEXT_LENGTH 100
#define MAX_LENGTH_ARR 10

// Begraensning paa printbare ascii-tegn.
#define MIN_CHAR 32    // Space
#define MAX_CHAR 126   // Tilde (~)
#define RANGE_SIZE 95  // 126 - 32 + 1

// Struct for sessioner.
typedef struct session {
    long long secret_key;              // Brugerens private, hemmelige noegle.
    long long public_key;             // Brugerens offentlige noegle.
    long long shared_secret;         // Den faelles, hemmelige krypteringsnoegle.
    int keys_generated;             // Tjekker om den private, hemmelige noegle er genereret.
    char text[TEXT_LENGTH];        // Plain text & Cipher text.
    int numbers[MAX_LENGTH_ARR];  // Laengden på krypteringsnoeglen.
} Session;


// Funktionsprototyper.

// UI og Input Validering.
void print_menu_start(void);                 // Menu 1
void print_menu_key(Session my_session);     // Menu 2
void print_menu_crypto(void);                // Menu 3
void print_brugervejledning(void);           // Brugervejledning
long long get_safe_long(long long min, long long max);

// Logik og Filhaandtering.
void save_session(Session current_session);
int load_session(Session *current_session);
void session_indlaest(Session current_session);
void session_ikke_indlaest(Session current_session);

// Diffie-Hellman noeglegenerering.
uint64_t modular_pow(uint64_t base, uint64_t exponent, uint64_t modulus);
long long generate_random_key();
void fetch_random_key(Session *my_session);
void fetch_manual_key(Session *my_session);
void generate_shared_key(Session *my_session, int *state);

// Krypteringsfunktioner.
void encrypt_text(char plain_text[], int numbers[], int arr_len);
void decrypt_text(char cipher_text[], int numbers[], int arr_len);
int get_length_for_array(long long ll);
void ll_to_intarr(long long ll, int numbers[], int length);
void encryption(Session my_session, char plain_text[], long long secret_key, int numbers[]);
void decryption(char cipher_text[], long long secret_key, int numbers[]);
int wrap_printable(int value);
char encrypt_char(char p, int k);
char decrypt_char(char c, int k);

#endif