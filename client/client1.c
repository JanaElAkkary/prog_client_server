#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void print_client_banner() {
    printf("\033[38;5;182m");  // Purple color
    printf("\n");
    printf("╔════════════════════════════════════╗\n");
    printf("║        JA HOLDING CLIENT           ║\n");
    printf("╠════════════════════════════════════╣\n");
    printf("║  Encryption : AES-128-CBC          ║\n");
    printf("║  Protocol   : SSL                  ║\n");
    printf("║  Status     : Connecting to server ║\n");
    printf("╚════════════════════════════════════╝\n\n");
    // printf("\033[0m");  // Reset color
}


unsigned char aes_key[16];
unsigned char aes_iv[16];

void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


void encrypt(unsigned char *plaintext, unsigned char *ciphertext, int len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ciphertext_len, len_tmp;

    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv);
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, len);
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len_tmp);
    ciphertext_len += len_tmp;

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    print_client_banner();

    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE] = {0};
    unsigned char encrypted_user[BUFFER_SIZE], encrypted_pass[BUFFER_SIZE];
    char username[50], password[50];

    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    connect(sock, (struct sockaddr *)&server_address, sizeof(server_address));

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_connect(ssl);

    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(aes_iv, sizeof(aes_iv));
    SSL_write(ssl, aes_key, 16);
    SSL_write(ssl, aes_iv, 16);

    int attempts=0;
    while (attempts<2){
        // Get username and password
        printf("Enter username: ");
        scanf("%s", username);
        printf("Enter password: ");
        scanf("%s", password);

        int user_len = strlen(username);
        int pass_len = strlen(password);

        memset(encrypted_user, 0, BUFFER_SIZE);
        memset(encrypted_pass, 0, BUFFER_SIZE);

     
        // Encrypt and print encrypted username
        encrypt((unsigned char*)username, encrypted_user, user_len);
        int enc_user_len = ((user_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
      
        
        // Encrypt and print encrypted password
        encrypt((unsigned char*)password, encrypted_pass, pass_len);
        int enc_pass_len = ((pass_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
   
        
        // Send encrypted data
        SSL_write(ssl, &user_len, sizeof(int));
        SSL_write(ssl, encrypted_user, enc_user_len);
        
        SSL_write(ssl, &pass_len, sizeof(int));
        SSL_write(ssl, encrypted_pass, enc_pass_len);

        memset(buffer, 0, BUFFER_SIZE);

        // Receive response from server
        // int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        // if (bytes_received > 0) {
        //     buffer[bytes_received] = '\0'; 
        //     printf("Server: %s\n", buffer);
        // } else {
        //     printf("No response from server.\n");
        //     close(sock);
        //     return 0;
        // }

        int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
        
            // Styled feedback with color reset to purple
            if (strcmp(buffer, "Authentication successful") == 0) {
                printf("\033[1;32m[✔] Authentication successful!\033[0m\033[38;5;182m\n");  
                int unread_count;
                SSL_read(ssl, &unread_count, sizeof(int));
                int has_messages;
                SSL_read(ssl, &has_messages, sizeof(int));
                if (has_messages) {
                    int msg_len;
                    SSL_read(ssl, &msg_len, sizeof(int));
                    char *inbox = malloc(msg_len + 1);
                    SSL_read(ssl, inbox, msg_len);
                    inbox[msg_len] = '\0';

                    printf("\033[38;5;182m[Messages for you]:\n%s\033[38;5;182m\n", inbox);
                    free(inbox);
                }
                

                    int choice = 0;
                while (1) {
                    printf("\n\033[1m\033[90m=========== MAIN MENU ===========\033[0m\n");
                    printf("\033[38;5;182m1. File Transfer\n");
                    printf("2. Message Sending (%d unread)\n", unread_count);
                    printf("3. Exit\n");
                    printf("\033[1m\033[90m=================================\033[0m\n");
                    printf("\033[38;5;182mEnter your choice (1-3): \033[0m");
                    scanf("%d", &choice);

                    SSL_write(ssl, &choice, sizeof(int));

                    if (choice == 1) {
                        int ftp_choice = 0;
                        while (1) {
                            printf("\n\033[1m\033[90m============= FTP MENU =============\033[0m\n");
                            printf("\033[38;5;182m1. Transfer an existing file\n");
                            printf("2. List available files (ls)\n");
                            printf("3. Create a new file\n");
                            printf("4. Delete an existing file\n");
                            printf("5. Exit to the main menu\n");
                            printf("\033[1m\033[90m====================================\033[0m\n");
                            printf("\033[38;5;182mEnter your FTP choice: \033[0m");
                            scanf("%d", &ftp_choice);

                            if (ftp_choice == 1) {
                                char filename[100];
                                FILE *fp = NULL;

                                while (1) {
                                    printf("\033[38;5;182mEnter filename to transfer (or type 'exit' to go back): ");
                                    scanf("%s", filename);

                                    if (strcmp(filename, "exit") == 0) break;

                                    fp = fopen(filename, "rb");
                                    if (!fp) {
                                        printf("\033[1;31m[✖] No file with this name. Try again or type 'exit'.\033[0m\n");
                                    } else {
                                        break;
                                    }
                                }

                                if (fp) {
                                    fseek(fp, 0, SEEK_END);
                                    long fsize = ftell(fp);
                                    rewind(fp);

                                    unsigned char *file_data = malloc(fsize);
                                    fread(file_data, 1, fsize, fp);
                                    fclose(fp);

                                    int filename_len = strlen(filename);
                                    int enc_file_len = ((fsize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
                                    
                                    unsigned char *enc_file = calloc(1, enc_file_len);
                                    encrypt(file_data, enc_file, fsize);

                                    SSL_write(ssl, &filename_len, sizeof(int));
                                    SSL_write(ssl, filename, filename_len);
                                    SSL_write(ssl, &fsize, sizeof(int));
                                    SSL_write(ssl, enc_file, enc_file_len);

                                    printf("\033[38;5;182m[✔] File '%s' transferred successfully.\033[0m\n", filename);

                                    free(file_data);
                                    free(enc_file);
                                }
                            }
                            else if (ftp_choice == 2) {
                                printf("\033[38;5;182m[✔] Listing files in client folder:\033[0m\n");
                                system("ls");
                            }
                            
                            else if (ftp_choice == 3) {
                                char new_filename[100], file_data[BUFFER_SIZE];
                                printf("\033[38;5;182mEnter new file name to create: ");
                                scanf("%s", new_filename);
                                getchar();  // Clear newline
                            
                                printf("\033[38;5;182mEnter file content (max %d characters): ", BUFFER_SIZE - 1);
                                fgets(file_data, BUFFER_SIZE, stdin);
                            
                                FILE *new_fp = fopen(new_filename, "w");
                                if (new_fp) {
                                    fputs(file_data, new_fp);
                                    fclose(new_fp);
                                    printf("\033[38;5;182m[✔] File '%s' created successfully.\033[0m\n", new_filename);
                                } else {
                                    printf("\033[1;31m[✖] Failed to create file.\033[0m\n");
                                }
                            }
                            
                            else if (ftp_choice == 4) {
                                char del_filename[100];
                                while (1) {
                                    printf("\033[38;5;182mEnter filename to delete (or type 'exit' to return): ");
                                    scanf("%s", del_filename);
                            
                                    if (strcmp(del_filename, "exit") == 0) break;
                            
                                    if (access(del_filename, F_OK) != 0) {
                                        printf("\033[1;31m[✖] File does not exist. Try again.\033[0m\n");
                                    } else {
                                        if (remove(del_filename) == 0) {
                                            printf("\033[38;5;182m[✔] File '%s' deleted successfully.\033[0m\n", del_filename);
                                            break;
                                        } else {
                                            printf("\033[1;31m[✖] Failed to delete file.\033[0m\n");
                                            break;
                                        }
                                    }
                                }
                            }
                            
                            else if (ftp_choice == 5) {
                                printf("\033[38;5;182mReturning to main menu...\033[0m\n");
                                int ftp_exit_signal = -1;
                                SSL_write(ssl, &ftp_exit_signal, sizeof(int));
                                break;
                            }
                            else {
                                printf("\033[1;31m[!] Invalid FTP choice. Please enter 1-5.\033[0m\n");
                            }
                        }
                    }
                    else if (choice == 2) {
                        int msg_choice;
                        printf("\n\033[1m\033[90m===== MESSAGE MENU =====\033[0m\n");
                        printf("\033[38;5;182m1. Send to server\n2. Send to another client\n 3.Return to main menu\n\033[0m");
                        printf("\033[1m\033[90m========================\033[0m\n");
                        printf("\033[38;5;182mEnter your message option: \033[0m");
                        scanf("%d", &msg_choice);
                        getchar(); 

                        if (msg_choice == 3) {
                            printf("\033[38;5;182mReturning to main menu...\033[0m\n");
                            SSL_write(ssl, &msg_choice, sizeof(int)); // still send to server to maintain sync
                            continue;
                        }

                        SSL_write(ssl, &msg_choice, sizeof(int));
                    
                       
                    
                        if (msg_choice == 1) {
                            char message[BUFFER_SIZE];
                            printf("\033[38;5;182mEnter your message: ");
                            fgets(message, BUFFER_SIZE, stdin);
                            message[strcspn(message, "\n")] = 0;
                    
                            int msg_len = strlen(message);
                            unsigned char enc_msg[BUFFER_SIZE];
                            encrypt((unsigned char *)message, enc_msg, msg_len);
                            int enc_msg_len = ((msg_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
                    
                            SSL_write(ssl, &msg_len, sizeof(int));
                            SSL_write(ssl, enc_msg, enc_msg_len);
                    
                            int reply_len = SSL_read(ssl, message, BUFFER_SIZE - 1);
                            if (reply_len > 0) {
                                message[reply_len] = '\0';
                                printf("\033[1;32m[✔] %s\033[0m\n", message);
                            }
                        } else if (msg_choice == 2) {
                            char recipient[50], message[BUFFER_SIZE];
                            printf("\033[38;5;182mEnter recipient username: ");
                            scanf("%s", recipient);
                            getchar();  // clear newline
                    
                            printf("\033[38;5;182mEnter your message: ");
                            fgets(message, BUFFER_SIZE, stdin);
                            message[strcspn(message, "\n")] = 0;
                    
                            int msg_len = strlen(message);
                            int rec_len = strlen(recipient);
                            unsigned char enc_msg[BUFFER_SIZE];
                            encrypt((unsigned char *)message, enc_msg, msg_len);
                            int enc_msg_len = ((msg_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
                    
                            SSL_write(ssl, &rec_len, sizeof(int));
                            SSL_write(ssl, recipient, rec_len);
                            SSL_write(ssl, &msg_len, sizeof(int));
                            SSL_write(ssl, enc_msg, enc_msg_len);
                    
                            int reply_len = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
                            if (reply_len > 0) {
                                buffer[reply_len] = '\0';
                                printf("\033[1;32m[✔] %s\033[0m\n", buffer);
                            }
                        } else {
                            printf("\033[1;31m[!] Invalid option.\033[0m\n");
                        }
                    }
                    
                    
                    else if (choice == 3) {
                        printf("\033[1;31m[✖] Exiting... Goodbye!\033[0m\n");
                        break;
                    }
                    else {
                        printf("\033[1;31m[!] Invalid choice. Please enter 1, 2, or 3.\033[0m\n");
                    }
                    SSL_read(ssl, &unread_count, sizeof(int));  // update unread message count

                }

                break; 

            } else if (strstr(buffer, "Try again") != NULL) {
                printf("\033[38;5;196m[!] Wrong username or password. Try again\033[0m\033[38;5;182m\n");

            } else if (strstr(buffer, "Authentication failed") != NULL) {
                printf("\033[1;31m[✖] Authentication failed!\033[0m\033[38;5;182m\n"); 
                break;
            
            
            }else {
                printf("Unexpected response: %s\n", buffer);
                break;
            }
        } else {
            printf("No response from server.\n");
            break;
        }
    
        


        // If authentication was successful, send a message to the server
        // if (strcmp((char*)buffer, "Authentication successful") == 0) {
        //     getchar();
        //     printf("Enter a message to send to the server: ");
        //     fgets(message, BUFFER_SIZE, stdin);
        //     message[strcspn(message, "\n")] = '\0';
        //     int msg_len = strlen(message);
        //     unsigned char encrypted_msg[BUFFER_SIZE];
        //     encrypt((unsigned char*)message, encrypted_msg, msg_len);
        //     int enc_msg_len = ((msg_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

        //     // Send length then encrypted message
        //     SSL_write(ssl, &msg_len, sizeof(int));
        //     SSL_write(ssl, encrypted_msg, enc_msg_len);

        //     // Receive acknowledgment from server
        //     memset(buffer, 0, BUFFER_SIZE);
        //     bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        //     if (bytes_received > 0) {
        //         buffer[bytes_received] = '\0';
        //         printf("Server: %s\n", buffer);
        //     }
        //    // Ask if user wants to send a file
        //    printf("Do you want to transfer a file? (y/n): ");
        //    char choice;
        //    scanf(" %c", &choice);
        //    getchar(); 

        //    if (choice == 'y' || choice == 'Y') {
        //        char filename[100];
        //        printf("Choose a file to send (marketing.txt / finance.txt / IT.txt): ");
        //        scanf("%s", filename);
        //        getchar(); 

        //        FILE *fp = fopen(filename, "rb");
        //        if (!fp) {
        //            perror("Failed to open the selected file");
        //        } else {
        //            // Send the filename length and name first
        //            int filename_len = strlen(filename);
        //            SSL_write(ssl, &filename_len, sizeof(int));
        //            SSL_write(ssl, filename, filename_len);

        //            fseek(fp, 0, SEEK_END);
        //            long fsize = ftell(fp);
        //            rewind(fp);

        //            unsigned char *file_data = malloc(fsize);
        //            fread(file_data, 1, fsize, fp);
        //            fclose(fp);

        //            unsigned char *enc_file = calloc(1, ((fsize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE);
        //            encrypt(file_data, enc_file, fsize);
        //            int enc_file_len = ((fsize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

        //            // Send length then encrypted file content
        //            SSL_write(ssl, &fsize, sizeof(int));
        //            SSL_write(ssl, enc_file, enc_file_len);

        //            printf("File '%s' sent successfully.\n", filename);
        //            free(file_data);
        //            free(enc_file);
        //        }
        //    }


         
        
    }
    

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}

