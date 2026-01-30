#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "kryptering.h" 

// Menuerne der vises til brugeren.

// MENU 1: Startmenu.
void print_menu_start(void) {
    printf("\n||================================================================||\n");
    printf("||}                                                              {||\n");
    printf("|||}                                                            {|||\n");    
    printf("||||}     !Velkommen Til P1-Projektets Krypteringsprogram!     {||||\n");
    printf("|||}                                                            {|||\n");
    printf("||}                                                              {||\n");
    printf("||================================================================||\n");
    printf("||      Dette program sikrer privat kommunikation, for alle.      ||\n");
    printf("||                                                                ||\n");
    printf("||------------ Vaelg en noegle paa 10 cifre [1] / [2] ------------||\n");
    printf("||---------------- Eller anvend din nuvaerende [3] ---------------||\n");
    printf("||                                                                ||\n");
    printf("|| [1]. Automatisk: Generer en tilfaeldig noegle. (Foreslaaet!)   ||\n");
    printf("|| [2]. Manuelt:    Indtast selv en noegle.                       ||\n");
    printf("||                                                                ||\n");
    printf("|| [3]. Indtast kommunikationspartners offentlige noegle.         ||\n");
    printf("||                                                                ||\n");
    printf("|| [9]. Hjaelp.                                                   ||\n");
    printf("|| [0]. Gem session og afslut programmet.                         ||\n");
    printf("||================================================================||\n");
    printf("Indtast valg: ");
}


// MENU 2: Efter den hemmelige noegle er valgt.
void print_menu_key(Session my_session) {
    my_session.public_key = modular_pow(GENERATOR, my_session.secret_key, PRIME_MODULUS);
    printf("\n                 ||----------------------------||");
    printf("\n                 || Din offentlige noegle er:  ||");
    printf("\n                 ||                            ||");
    printf("\n                 ||        [%-10lld]        ||", my_session.public_key);
    printf("\n                 ||                            ||");
    printf("\n||================================================================||\n");   
    printf("||------------------- Indtast offentlig noegle -------------------||\n");
    printf("||                                                                ||\n");
    printf("|| [3]. Indtast kommunikationspartners offentlige noegle.         ||\n");
    printf("||                                                                ||\n");
    printf("|| [8]. Gaa tilbage.                                              ||\n");
    printf("|| [9]. Hjaelp.                                                   ||\n");
    printf("|| [0]. Gem session og afslut programmet.                         ||\n");
    printf("||================================================================||\n");
    printf("Indtast valg: ");
}


// MENU 3: Efter den faelles noegle er genereret. (Klar til kryptering).
void print_menu_crypto(void) {
    printf("||================================================================||\n");
    printf("||                                                                ||\n");
    printf("||                      !Klar til kryptering!                     ||\n");
    printf("||                                                                ||");
    printf("\n||================================================================||\n");   
    printf("||---------------------- Krypter / Dekrypter ---------------------||\n");
    printf("||                                                                ||\n");
    printf("|| [5]. Krypter besked.                                           ||\n");
    printf("|| [6]. Dekrypter besked.                                         ||\n");
    printf("||                                                                ||\n");
    printf("|| [8]. Gaa tilbage.                                              ||\n");
    printf("|| [9]. Hjaelp.                                                   ||\n");
    printf("|| [0]. Gem session og afslut programmet.                         ||\n");
    printf("||================================================================||\n");
    printf("Indtast valg: ");
}


// Funktion til input-validering.
long long get_safe_long(long long min, long long max) {
    long long value;
    int status;
    char skip_ch;
    
    while (1) {
        status = scanf("%lld", &value);
        
// Ryd buffer for potentielle, resterende tegn i input.
        do {
            scanf("%c", &skip_ch);
        } while (skip_ch != '\n');

// Validerer om input er et gyldigt tal.
        if (status == 1 && value >= min && value <= max) {
            return value; 
        } else {
            printf("Fejl: Indtast venligst et tal på 10 cifre!");
        }
    }
}


// Opretter backup.txt fil, hvis den ikke allerede eksisterer.
// Gemmer noeglen til en fil. 
void save_session(Session current_session) {
    FILE *fp = fopen("backup.txt", "w");
    if (fp != NULL) {
        
// Vi gemmer secret_key og status. public_key udregenes igen, naar backup hentes.
        fprintf(fp, "%lld %d", current_session.secret_key, current_session.keys_generated);
        fclose(fp);  
        printf("--> Session gemt korrekt.\n");
    } else {
        printf("--> Fejl: Kunne ikke gemme filen.\n");
    }
}


// Forsoeger at indlaese session fra backup-fil.
int load_session(Session *current_session) {
    FILE *fp = fopen("backup.txt", "r");
    if (fp != NULL) {
        
        // Vi bruger -> fordi current_session er en pointer. Returnerer 1 hvis det lykkedes, ellers 0.
        fscanf(fp, "%lld %d", &current_session->secret_key, &current_session->keys_generated);
        fclose(fp);
        return 1; 
    }
    return 0;
}


// Hvis session kan findes.
void session_indlaest(Session my_session){
    printf("\n||================================================================||\n");
    printf("||                  !Tidligere session indlaest!                  ||\n");
    printf("||           Nuvaerende hemmelige noegle:  [%-10lld]           ||\n", my_session.secret_key);
    printf("||                                                                ||\n");
    
    if (my_session.keys_generated) {
        my_session.public_key = modular_pow(GENERATOR, my_session.secret_key, PRIME_MODULUS);
        printf("||           Nuvaerende offentlige noegle: [%-10lld]           ||", my_session.public_key);
        printf("\n||                                                                ||");
    }
}


// Hvis session ikke kan findes.
void session_ikke_indlaest(Session my_session){
    printf("\n||================================================================||\n");
    printf("||                !Ingen tidligere session fundet!                ||\n"); 
    printf("||                                                                ||");
}


// Genererer et tilfaeldigt 10 cifret tal.
long long generate_random_key() {
    int i;
    char number[11]; // 10 cifre + NULL terminator.
    
// Sikrer at foerste ciffer ikke er 0.
    number[0] = (rand() % 9) + '1'; 

    for(i = 1; i < 10; i++){
        number[i] = (rand() % 10) + '0';
    }
// NULL terminator.
        number[10] = '\0'; 

// Konverterer string, til long long integer.
    return atoll(number); 
}


//Diffie-Hellman Noegleudveksling.
uint64_t modular_pow(uint64_t generator, uint64_t secret_key, uint64_t prime_number) {
    uint64_t result = 1;
    generator %= prime_number;

    while (secret_key > 0) {
        if (secret_key & 1) { 
            result = (result * generator) % prime_number;
        }

        generator = (generator * generator) % prime_number; 
        secret_key >>= 1; 
    }
    return result;
}


// Genererer tilfaeldigt tal, og angiver det som secret_key.
void fetch_random_key(Session *my_session){
    my_session->secret_key = generate_random_key();
    my_session->public_key = modular_pow(GENERATOR, my_session->secret_key, PRIME_MODULUS);
    my_session->keys_generated = 1;    
    save_session(*my_session); 
}


// Manuel indtastning af secret_key.
void fetch_manual_key(Session *my_session){
    printf("Indtast din hemmelige noegle: ");
    my_session->secret_key = get_safe_long(999999999, 9999999999);
    my_session->public_key = modular_pow(GENERATOR, my_session->secret_key, PRIME_MODULUS);
    my_session->keys_generated = 1;
    save_session(*my_session); 
}


// Genererer den delte, hemmelige noegle, til kryptering.
void generate_shared_key(Session *my_session, int *state){
    if (my_session->keys_generated == 0) {
        printf("\nFEJL: Du mangler en noegle! (Vaelg 1 eller 2) for at gaa videre!\n");
        *state = 0; 
    } else {
        printf("Indtast kommunikationspartners offentlige noegle: ");
        long long partner_pub = get_safe_long(0, 99999999999LL);

        my_session->shared_secret = modular_pow(partner_pub, my_session->secret_key, PRIME_MODULUS);
        printf("\n||================================================================||\n");
        printf("||******************* FAELLES NOEGLE BEREGNET! *******************||\n");
        *state = 2;
    }
}


// Funktion der looper gennem input-tekst og krypterer den ud fra keyword fra krypteringsnoeglen.
void encrypt_text(char plaintext[], int numbers[], int arr_len) {
    int text_length = strlen(plaintext);
    int j = 0;
    int i = 0;

    for (i; i < text_length; i++)
    {
        if (j != arr_len) {
            plaintext[i] = encrypt_char(plaintext[i], numbers[j]);
            j++;
        } else {
            i--;
            j = 0;
        }
    }
    plaintext[i] = '\0';
}


// Funktion der looper gennem input-tekst og dekrypterer den ud fra keyword fra krypteringsnoeglen.
void decrypt_text(char plaintext[], int numbers[], int arr_len) {
    int text_length = strlen(plaintext);
    int j = 0;
    int i = 0;

    for (i; i < text_length; i++)
    {
        if (j != arr_len) {
            plaintext[i] = decrypt_char(plaintext[i], numbers[j]);
            j++;
        } else {
            i--;
            j = 0;
        }  
    }
    plaintext[i] = '\0';
}


// Funktion der konverterer long long til int array.
void ll_to_intarr(long long ll, int numbers[], int length) { 
    char str[100];
    int length_ll = snprintf(str, sizeof(str), "%lld", ll);
    int j = 0;

    if (length_ll > 5) {
      for(int i = 0; i < length; i++) {
  
          if ((i == length - 1) && (length_ll % 2 == 1)) {
              numbers[i] = (str[j] - '0'); 
          } else {
              numbers[i] = (str[j] - '0') * 10 + (str[j+1] - '0');  
          }
          
          j += 2;
      }
   } else {
      for (size_t i = 0; i < length_ll; i++) {
        numbers[i] = (str[j] - '0');
        j++;
      }
    }
}


// Tager et tal og retunerer hvor mange pladser der skal vaere i int-arrayet.
int get_length_for_array(long long ll) {
    char str[100];
    int digits = snprintf(str, sizeof(str), "%lld", ll);
    int arr_len = (int) ceil(digits/2.0);
    return arr_len;
}


int wrap_printable(int value) {
    value -= MIN_CHAR;           // Shift to 0-based
    value %= RANGE_SIZE;         // Modulo 95
    if (value < 0) {
        value += RANGE_SIZE;     // Handle negative
    }
    return value + MIN_CHAR;     // Shift back to 32-126
}


char encrypt_char(char p, int k) {
    return wrap_printable(p + k);
}
char decrypt_char(char c, int k) {
    return wrap_printable(c - k);
}


// Krypteringsfunktion.
void encryption(Session my_session, char plain_text[], long long shared_secret, int numbers[]) {
    my_session.public_key = modular_pow(GENERATOR, my_session.secret_key, PRIME_MODULUS);
    printf("Indtast den tekst du oensker at kryptere: ");
    scanf(" %[^\n]", plain_text);

    int length = get_length_for_array(shared_secret);
    ll_to_intarr(shared_secret, numbers, length);

    encrypt_text(plain_text, numbers, length);
    printf("\n\n");
    printf("\n||================================================================||");
    printf("\n||      Del din offentlige noegle, og den krypterede besked!      ||");
    printf("\n||================================================================||\n");
    printf("\nMin offentlige noegle:");
    printf("\n[%lld]", my_session.public_key);
    printf("\n\nKrypteret tekst:");
    printf("\n%s\n\n", plain_text);
}

// Dekrypteringsfunktion.
void decryption(char cipher_text[], long long shared_secret, int numbers[]) {
    printf("Indtast den tekst du oensker at dekryptere: ");
    scanf(" %[^\n]", cipher_text);

    int length = get_length_for_array(shared_secret);
    ll_to_intarr(shared_secret, numbers, length);
    
    decrypt_text(cipher_text, numbers, length);
    printf("\n\n");
    printf("Dekrypteret tekst: \n%s\n\n", cipher_text);
}


// Brugervejledning.
void print_brugervejledning(void) {
    printf("\n||================================================================||\n");   
    printf("||--------------- !Tak for at bruge vores program! ---------------||\n");
    printf("||                                                                ||\n");
    printf("||     Dette program anvender Diffie-Hellman noegleudveksling     ||\n");
    printf("||     sammen med en Vigenere-inspireret krypteringsalgoritme     ||\n");
    printf("||     til at sikre privat kommunikation og beskytte din data!    ||\n");
    printf("||                                                                ||\n");
    printf("||             Krypteringsprocessen bestaar af 4 trin:            ||\n");
    printf("||----------------------------------------------------------------||\n");
    printf("|| 1). Vaelg et hemmeligt tal paa 10 cifre.                       ||\n");
    printf("||                                                                ||\n");
    printf("|| 2). Send den genererede, offentlige noegle til modtageren.     ||\n");
    printf("||                                                                ||\n");
    printf("|| 3). Angiv den modtagne, offentlige noegle.                     ||\n");
    printf("||                                                                ||\n");
    printf("|| 4). Skriv din private besked, og send den til modtageren,      ||\n");
    printf("||     eller indsaet den krypterede besked for at aflaese den!    ||\n");
    printf("||----------------------------------------------------------------||\n");
    printf("||                        God fornoejelse!                        ||\n");
    printf("||================================================================||\n");
}