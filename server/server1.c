#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>   
#include <sys/types.h> 
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <pthread.h>


#define PORT 8080
#define BUFFER_SIZE 1024


void print_server_banner() {
    printf("\033[38;5;206m");  // Start pink
    printf("\n");
    printf("╔════════════════════════════════════╗\n");
    printf("║        JA HOLDING SERVER           ║\n");
    printf("╠════════════════════════════════════╣\n");
    printf("║  AES-128-CBC Encryption Enabled    ║\n");
    printf("║  SSL Protocol Active               ║\n");
    printf("║  Multithreading: ON                ║\n");
    printf("║  Listening on port %-5d           ║\n", PORT);
    printf("╚════════════════════════════════════╝\n\n");
    // printf("\033[0m");     // Reset color
}

unsigned char aes_key[16];
unsigned char aes_iv[16];

void log_action(const char *username, const char *action) {
    FILE *log_file = fopen("logs.txt", "a");
    if (log_file) {
        fprintf(log_file, "%s: %s\n", username, action);
        fclose(log_file);
    } else {
        perror("[ERROR] Could not open logs.txt");
    }
}

struct client_info{
    int socket;
    SSL *ssl;
};


void print_hex(const char *label, const unsigned char *data, int len){
    printf("%s", label);
    for (int i=0 ; i< len; ++i)
        printf ("%02x", data[i]);
    printf ("\n");
}

void decrypt(unsigned char *ciphertext, unsigned char *plaintext, int len, unsigned char *key, unsigned char *iv){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int plaintext_len, len_tmp;

    if(!ctx){
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return;
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, len);
    EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len_tmp);
    plaintext_len += len_tmp;
    plaintext[plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
}
int is_path_accessible(const char *path, const char *role, const char *dept) {
    if (strcmp(role, "Top") == 0) return 1;  // Top can access everything

    // Entry: can only read from their department client folder
    if (strcmp(role, "Entry") == 0) {
        char expected_path[100];
        snprintf(expected_path, sizeof(expected_path), "client/%s_c/", dept);
        return strstr(path, expected_path) != NULL;
    }

    // Medium: can access their department folder in client and server
    if (strcmp(role, "Medium") == 0) {
        char client_path[100], server_path[100];
        snprintf(client_path, sizeof(client_path), "client/%s_c/", dept);
        snprintf(server_path, sizeof(server_path), "server/%s_s/", dept);
        return strstr(path, client_path) != NULL || strstr(path, server_path) != NULL;
    }

    return 0;  
}


int authenticate(const char *user, const char *pass, char *role, char *dept) {
    FILE *fp = fopen("users.txt", "r");
    if (!fp) {
        perror("[ERROR] Could not open users.txt");
        return 0;
    }

    char stored_user[50], stored_pass[50],stored_role[20],stored_dept[30];
    while (fscanf(fp, "%s %s", stored_user, stored_pass,stored_role,stored_dept) == 4) {
        if (strcmp(user, stored_user) == 0 && strcmp(pass, stored_pass) == 0) {
            strcpy(role,stored_role);
            strcpy(dept,stored_dept);
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}
int get_message_count(const char *username) {
    char path[100];
    snprintf(path, sizeof(path), "messages/%s.txt", username);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    int count = 0;
    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp)) count++;
    fclose(fp);
    return count;
}

void deliver_messages(const char *username) {
    char path[100];
    snprintf(path, sizeof(path), "messages/%s.txt", username);
    FILE *fp = fopen(path, "r");
    if (!fp) return;

    printf("\n\033[1;36m[Messages for %s]:\033[0m\n", username);
    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp)) {
        printf("  \033[38;5;206m%s\033[0m", line);
    }
    fclose(fp);
    remove(path); // clear inbox
}

char* deliver_messages_to_client(const char *username) {
    char path[100];
    snprintf(path, sizeof(path), "messages/%s.txt", username);
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;

    static char all_msgs[BUFFER_SIZE * 10] = {0}; 
    char line[BUFFER_SIZE];

    while (fgets(line, sizeof(line), fp)) {
        strcat(all_msgs, line);
    }

    fclose(fp);
    remove(path); 
    return all_msgs;
}

void *handle_client(void *arg) {
    struct client_info *cinfo = (struct client_info *)arg;
    SSL *ssl = cinfo->ssl;
    int client_socket = cinfo->socket;
    free(cinfo);



    unsigned char aes_key[16];
    unsigned char aes_iv[16];
    unsigned char encrypted[BUFFER_SIZE], decrypted_user[BUFFER_SIZE], decrypted_pass[BUFFER_SIZE], buffer[BUFFER_SIZE];
    char client_username[BUFFER_SIZE]; 
    char user_role[20], user_dept[30];

    SSL_read(ssl, aes_key, 16);
    SSL_read(ssl, aes_iv, 16);
    
    int attempts = 0;
    while (attempts < 2) {
        int user_len, pass_len;

        SSL_read(ssl, &user_len, sizeof(int));
        int enc_user_len = ((user_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        SSL_read(ssl, encrypted, enc_user_len);
        memset(decrypted_user, 0, BUFFER_SIZE);
        decrypt(encrypted, decrypted_user, enc_user_len, aes_key, aes_iv);
        strcpy(client_username, (char *)decrypted_user);
        printf("\033[38;5;206mDecrypted Username: %s\n", decrypted_user);
        // fflush(stdout);
        

        SSL_read(ssl, &pass_len, sizeof(int));
        int enc_pass_len = ((pass_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        SSL_read(ssl, encrypted, enc_pass_len);
        memset(decrypted_pass, 0, BUFFER_SIZE);
        decrypt(encrypted, decrypted_pass, enc_pass_len, aes_key, aes_iv);
        printf("\033[38;5;206mDecrypted Password: %s\n", decrypted_pass);
        // fflush(stdout);
        

        if (authenticate((char *)decrypted_user, (char *)decrypted_pass,user_role,user_dept)) {
            printf("Authenticated Role: %s | Department: %s\n", user_role, user_dept);
            log_action(client_username, "authenticated successfully");
            printf("\033[1;32m[\u2714] Authentication successful!\033[0m\033[38;5;206m\n");
            SSL_write(ssl, "Authentication successful", strlen("Authentication successful"));
            if (access("messages", F_OK) == -1) {
                mkdir("messages", 0777);  
            }              
            char *inbox = deliver_messages_to_client(client_username);
            int has_messages = inbox && strlen(inbox) > 0;
            SSL_write(ssl, &has_messages, sizeof(int));
            if (has_messages) {
                int msg_len = strlen(inbox);
                SSL_write(ssl, &msg_len, sizeof(int));
                SSL_write(ssl, inbox, msg_len);
            }
 
            int msg_count = get_message_count(client_username);
            SSL_write(ssl, &msg_count, sizeof(int));  


            int menu_choice;
            while (SSL_read(ssl, &menu_choice, sizeof(int)) > 0) {
                printf("\033[38;5;206mClient selected menu option: %d\n", menu_choice);

                switch (menu_choice) {
                    case 1: {
                        printf("Client entered FTP submenu.\n");
                        log_action(client_username, "entered FTP menu");

                        int filename_len;
                        if (SSL_read(ssl, &filename_len, sizeof(int)) <= 0) break;

                        if (filename_len == -1) {
                            printf("Client exited FTP submenu.\n");
                            log_action(client_username, "exited FTP submenu");
                        
                            msg_count = get_message_count(client_username);  
                            SSL_write(ssl, &msg_count, sizeof(int));         
                        
                            break;
                        }
                        
                        char original_filename[100] = {0};
                        if (SSL_read(ssl, original_filename, filename_len) <= 0) break;

                        log_action(client_username, "transferring a file");

                        int file_size;
                        if (SSL_read(ssl, &file_size, sizeof(int)) <= 0) break;

                        int enc_file_len = ((file_size / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
                        unsigned char *enc_file = malloc(enc_file_len);
                        unsigned char *dec_file = calloc(1, enc_file_len + AES_BLOCK_SIZE);

                        int total_received = 0;
                        while (total_received < enc_file_len) {
                            int r = SSL_read(ssl, enc_file + total_received, enc_file_len - total_received);
                            if (r <= 0) break;
                            total_received += r;
                        }

                        decrypt(enc_file, dec_file, enc_file_len, aes_key, aes_iv);

                        char base_name[128];
                        char *dot = strrchr(original_filename, '.');
                        if (dot) *dot = '\0';
                        snprintf(base_name, sizeof(base_name), "received_%s", original_filename);

                        char out_filename[160];
                        int index = 1;
                        do {
                            snprintf(out_filename, sizeof(out_filename), "%s%d.txt", base_name, index);
                            FILE *test = fopen(out_filename, "r");
                            if (test) {
                                fclose(test);
                                index++;
                            } else {
                                break;
                            }
                        } while (1);

                        if (!is_path_accessible(out_filename, user_role, user_dept)) {
                            log_action(client_username, "unauthorized path access attempt");
                            SSL_write(ssl, "Access Denied: You are not authorized to write here.", strlen("Access Denied"));
                            break;
                        }

                        FILE *out = fopen(out_filename, "wb");
                        fwrite(dec_file, 1, file_size, out);
                        fclose(out);

                        char log_msg[200];
                        snprintf(log_msg, sizeof(log_msg), "\033[38;5;206muploaded file and saved as %s", out_filename);
                        log_action(client_username, log_msg);

                        free(enc_file);
                        free(dec_file);
                        break;
                    }
                    case 2: {
                        printf(" Client selected Message Sending.\n");
                        log_action(client_username, "selected Message Sending");
                    
                        int msg_type;
                        if (SSL_read(ssl, &msg_type, sizeof(int)) <= 0) break;

                        if (msg_type == 3) {
                            printf("Client exited Message submenu.\n");
                            log_action(client_username, "exited Message submenu");
                        
                            msg_count = get_message_count(client_username);  
                            SSL_write(ssl, &msg_count, sizeof(int));
                            break;
                        }
                    
                        if (msg_type == 1) {
                            int msg_len;
                            if (SSL_read(ssl, &msg_len, sizeof(int)) <= 0) break;
                    
                            int enc_msg_len = ((msg_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
                            unsigned char *enc_msg = malloc(enc_msg_len);
                            unsigned char *dec_msg = calloc(1, enc_msg_len + AES_BLOCK_SIZE);
                    
                            int total_received = 0;
                            while (total_received < enc_msg_len) {
                                int r = SSL_read(ssl, enc_msg + total_received, enc_msg_len - total_received);
                                if (r <= 0) break;
                                total_received += r;
                            }
                    
                            decrypt(enc_msg, dec_msg, enc_msg_len, aes_key, aes_iv);
                            printf("\033[38;5;206m[Server Received Message]: %s\033[0m\n", dec_msg);
                    
                            char log_msg[BUFFER_SIZE + 100];
                            snprintf(log_msg, sizeof(log_msg), "\033[38;5;206msent message to server: \"%s\"", dec_msg);
                            log_action(client_username, log_msg);
                            SSL_write(ssl, "Message delivered to server", strlen("Message delivered to server"));
                    
                            free(enc_msg);
                            free(dec_msg);
                        } else if (msg_type == 2) {
                            char recipient[50];
                            int rec_len, msg_len;
                    
                            SSL_read(ssl, &rec_len, sizeof(int));
                            SSL_read(ssl, recipient, rec_len);
                            recipient[rec_len] = '\0';
                    
                            SSL_read(ssl, &msg_len, sizeof(int));
                            int enc_msg_len = ((msg_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

                    
                            unsigned char *enc_msg = malloc(enc_msg_len);
                            unsigned char *dec_msg = calloc(1, enc_msg_len + AES_BLOCK_SIZE);
                    
                            int total_received = 0;
                            while (total_received < enc_msg_len) {
                                int r = SSL_read(ssl, enc_msg + total_received, enc_msg_len - total_received);
                                if (r <= 0) break;
                                total_received += r;
                            }
                    
                            decrypt(enc_msg, dec_msg, enc_msg_len, aes_key, aes_iv);
                    
                            char msg_path[100];
                            snprintf(msg_path, sizeof(msg_path), "messages/%s.txt", recipient);
                            FILE *fp = fopen(msg_path, "a");
                            if (fp) {
                                fprintf(fp, "From %s: %s\n", client_username, dec_msg);
                                fclose(fp);
                                log_action(client_username, "sent message to another client");
                                SSL_write(ssl, "Message sent to client", strlen("Message sent to client"));
                            } else {
                                log_action(client_username, "failed to message client: Unable to open file");
                                SSL_write(ssl, "Failed to send message: Unable to write to file", strlen("Failed to send message"));
                            }
                            
                    
                            free(enc_msg);
                            free(dec_msg);
                        }
        

                        msg_count = get_message_count(client_username);
                        SSL_write(ssl, &msg_count, sizeof(int));
                        break;
                    }
                    
                        
                    case 3:
                        printf(" Client exited the application.\n");
                        log_action(client_username, "exited the application");
                        goto end_session;
                    default:
                        printf("Client selected unknown main menu option.\n");
                        log_action(client_username, "selected unknown main menu option");
                        break;
                }
            }
            break;
            msg_count = get_message_count(client_username);
            SSL_write(ssl, &msg_count, sizeof(int));

        } else {
            printf("\033[1;31m[\u2716] Authentication failed!\033[0m\033[38;5;206m\n");
            attempts++;
            if (attempts < 2) {
                const char *msg = "Wrong username or password. Try again";
                SSL_write(ssl, msg, strlen(msg));
            } else {
                const char *msg = "Authentication failed";
                SSL_write(ssl, msg, strlen(msg));
                goto end_session;  
            }
        }
    }

end_session:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
    printf("\033[38;5;206m==================================== NEW CLIENT ====================================\n\n");
    pthread_exit(NULL);
}

int main() {
    print_server_banner();

    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(new_socket);
            SSL_free(ssl);
            continue;
        }

        struct client_info *cinfo = malloc(sizeof(struct client_info));
        cinfo->socket = new_socket;
        cinfo->ssl = ssl;

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, (void *)cinfo);
        pthread_detach(tid);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    printf("\033[38;5;206mServer shutting down...\n");
    return 0;
}