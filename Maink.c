#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "kryptering.h" 

int main(void) {
    srand(time(NULL)); 

// Session nulstilles.
    Session my_session = {0, 0, 0, 0, {0}, {0}}; 

// Variabler til styring af menuer 0, 1 eller 2.
    int state = 0;
    int choice;

    if (load_session(&my_session)) {
        session_indlaest(my_session);
    } else {
        session_ikke_indlaest(my_session);
    }

    
// Menuen der vises, baseret paa state.
    do {
        if (state == 0) {
            print_menu_start();           // Vis Menu 1.
            choice = (int)get_safe_long(0, 9);
        } 
        else if (state == 1) {
            print_menu_key(my_session);   // Vis Menu 2.
            choice = (int)get_safe_long(0, 9);
        } 
        else if (state == 2) {
            print_menu_crypto();          // Vis Menu 3.
            choice = (int)get_safe_long(0, 9);
        }

        switch (choice) {
            case 1: // Automatisk noegle.
                if (state == 0){ 
                    fetch_random_key(&my_session);
                    state = 1;
                }
                break;

            case 2: // Manuel noegle.
                if (state == 0){
                    fetch_manual_key(&my_session);
                    state = 1; 
                }
                break;

            case 3: // Beregner faelles noegle.
                if (state == 0 || 1) {
                    generate_shared_key(&my_session, &state);
                }
                break;

            case 5: // Krypterer input-tekst.
                if (state == 2) {
                    encryption(my_session, my_session.text, my_session.shared_secret, my_session.numbers);
                }
                break;
                
            case 6: // Dekrypterer input-tekst.
                if (state == 2) {
                    decryption(my_session.text, my_session.shared_secret, my_session.numbers);
                }
                break;

            case 8: // Gaar tilbage til tidligere menu.
                if (state > 0) {
                    state--; 
                    printf("\nGaar tilbage...\n");
                }
                break;
                
            case 9: // Printer brugervejledning.
                print_brugervejledning();
                break;

            case 0: // Gem og afslut, i alle menuer.
                save_session(my_session);
                printf("Afslutter...\n");
                break;
                
            default:
                printf("Ugyldigt valg i denne menu.\n");
                break;
        }
    } while (choice != 0);
    return 0;
}