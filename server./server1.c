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
#include <pthread.h>


#define PORT 8080
#define BUFFER_SIZE 1024

unsigned char aes_key[16];
unsigned char aes_iv[16];

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

int authenticate(const char *user, const char *pass) {
    FILE *fp = fopen("users.txt", "r");
    if (!fp) {
        perror("[ERROR] Could not open users.txt");
        return 0;
    }

    char stored_user[50], stored_pass[50];
    while (fscanf(fp, "%s %s", stored_user, stored_pass) == 2) {
        if (strcmp(user, stored_user) == 0 && strcmp(pass, stored_pass) == 0) {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}
void *handle_client(void *arg) {
    struct client_info *cinfo = (struct client_info *)arg;
    SSL *ssl = cinfo->ssl;
    int client_socket = cinfo->socket;
    free(cinfo);



    unsigned char aes_key[16];
    unsigned char aes_iv[16];
    unsigned char encrypted[BUFFER_SIZE], decrypted_user[BUFFER_SIZE], decrypted_pass[BUFFER_SIZE], buffer[BUFFER_SIZE];

    SSL_read(ssl, aes_key, 16);
    SSL_read(ssl, aes_iv, 16);


    int attempts = 0;
    while (attempts < 2) {
        int user_len, pass_len;

        // Receive and show encrypted username
        SSL_read(ssl, &user_len, sizeof(int));
        int enc_user_len = ((user_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        SSL_read(ssl, encrypted, enc_user_len);
        print_hex("Encrypted Username: ", encrypted, enc_user_len);

        memset(decrypted_user, 0, BUFFER_SIZE);
        decrypt(encrypted, decrypted_user, enc_user_len, aes_key, aes_iv);
        printf("Decrypted Username: %s\n", decrypted_user);

        // Receive and show encrypted password
        SSL_read(ssl, &pass_len, sizeof(int));
        int enc_pass_len = ((pass_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        SSL_read(ssl, encrypted, enc_pass_len);
        print_hex("Encrypted Password: ", encrypted, enc_pass_len);

        memset(decrypted_pass, 0, BUFFER_SIZE);
        decrypt(encrypted, decrypted_pass, enc_pass_len, aes_key, aes_iv);
        printf("Decrypted Password: %s\n", decrypted_pass);

        if (authenticate((char *)decrypted_user, (char *)decrypted_pass)) {
            printf("Authentication successful\n");
            SSL_write(ssl, "Authentication successful", strlen("Authentication successful"));

            int msg_len;
            SSL_read(ssl, &msg_len, sizeof(int));
            int enc_msg_len = ((msg_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
            SSL_read(ssl, encrypted, enc_msg_len);
            print_hex("Encrypted Message from Client: ", encrypted, enc_msg_len);

            memset(buffer, 0, BUFFER_SIZE);
            decrypt(encrypted, buffer, enc_msg_len, aes_key, aes_iv);
            printf("Decrypted Client Message: %s\n", buffer);
            SSL_write(ssl, "Message received", strlen("Message received"));
            
             // Receive filename length and name
             int filename_len;
             if (SSL_read(ssl, &filename_len, sizeof(int)) <= 0) return NULL;
 
             char original_filename[100] = {0};
             if (SSL_read(ssl, original_filename, filename_len) <= 0) return NULL;
 
             printf("Receiving file: %s\n", original_filename);
 
             // Receive file size and encrypted content
             int file_size;
             if (SSL_read(ssl, &file_size, sizeof(int)) <= 0) return NULL;
 
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
 
             // Build unique filename based on input
             char base_name[100];
             snprintf(base_name, sizeof(base_name), "received_%.*s", (int)(strrchr(original_filename, '.') - original_filename), original_filename);
 
             char out_filename[120];
             int file_index = 1;
             do {
                 snprintf(out_filename, sizeof(out_filename), "%s%d.txt", base_name, file_index);
                 FILE *test = fopen(out_filename, "r");
                 if (test) {
                     fclose(test);
                     file_index++;
                 } else {
                     break;
                 }
             } while (1);
 
             // Save the file
             FILE *out = fopen(out_filename, "wb");
             fwrite(dec_file, 1, file_size, out);
             fclose(out);
 
             printf("Saved received file as: %s\n", out_filename);
             free(enc_file);
             free(dec_file);
         
 

            break;
        } else {
            printf("Authentication failed\n");
            attempts++;
            const char *msg = (attempts < 2)
                ? "Wrong username or password. Try again"
                : "Authentication failed";
            SSL_write(ssl, msg, strlen(msg));
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);

    printf("==================================== NEW CLIENT ====================================\n\n");

    pthread_exit(NULL);
    }
int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    unsigned char encrypted[BUFFER_SIZE], decrypted_user[BUFFER_SIZE], decrypted_pass[BUFFER_SIZE], buffer[BUFFER_SIZE];

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


    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }


    // Define server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

       // Multithreaded accept loop
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

    // Close sockets
    close(server_fd);
    SSL_CTX_free(ctx);
    printf("Server shutting down...\n");

    return 0;
}
