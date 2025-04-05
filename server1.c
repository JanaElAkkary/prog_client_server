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

unsigned char aes_key[16];
unsigned char aes_iv[16];

const char *valid_users[2][2] = {
    {"jana", "jana123"},
    {"adham", "adham123"}
};

void print_hex(const char *label, const unsigned char *data, int len){
    printf("%s", label);
    for (int i=0 ; i< len; ++i)
        printf ("%02x", data[i]);
    printf ("\n");
}

void decrypt(unsigned char *ciphertext, unsigned char *plaintext, int len){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int plaintext_len, len_tmp;

    if(!ctx){
        fprintf(stderr,"EVP_CIPHER_CTX_new failed \n");
        return;
    }
   EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(),NULL, aes_key, aes_iv);
   EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, len);
   EVP_DecryptFinal_ex(ctx,plaintext+plaintext_len, &len_tmp);
   plaintext_len += len_tmp;
   plaintext [plaintext_len]='\0';
   EVP_CIPHER_CTX_free(ctx); 
}

int authenticate(const char *user, const char *pass) {
    for (int i = 0; i < 2; i++) {
        if (strcmp(user, valid_users[i][0]) == 0 && strcmp(pass, valid_users[i][1]) == 0) {
            return 1; // Success
        }
    }
    return 0;
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

    // Accept client connection
    new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    if (new_socket < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, new_socket);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(new_socket);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    SSL_read(ssl, aes_key, 16);
    SSL_read(ssl, aes_iv, 16);

    int attempts=0;
    while (attempts<2){
        int user_len, pass_len;

      // Receive and show encrypted username
        SSL_read(ssl, &user_len, sizeof(int));
        int enc_user_len = ((user_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        SSL_read(ssl, encrypted, enc_user_len);
        print_hex("Encrypted Username: ", encrypted, enc_user_len);

        // CLEAR BUFFER BEFORE decrypt()
        memset(decrypted_user, 0, BUFFER_SIZE);
        decrypt(encrypted, decrypted_user, enc_user_len);
        printf("Decrypted Username: %s\n", decrypted_user);


        // Receive and show encrypted password
        SSL_read(ssl, &pass_len, sizeof(int));
        int enc_pass_len = ((pass_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        SSL_read(ssl, encrypted, enc_pass_len);
        print_hex("Encrypted Password: ", encrypted, enc_pass_len);

        // CLEAR BUFFER BEFORE decrypt()
        memset(decrypted_pass, 0, BUFFER_SIZE);
        decrypt(encrypted, decrypted_pass, enc_pass_len);
        printf("Decrypted Password: %s\n", decrypted_pass);


        if (authenticate((char*)decrypted_user, (char*)decrypted_pass)) {
            SSL_write(ssl, "Authentication successful", strlen("Authentication successful"));
    
            // Read final encrypted message
            int msg_len;
            SSL_read(ssl, &msg_len, sizeof(int));
            int enc_msg_len = ((msg_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
            SSL_read(ssl, encrypted, enc_msg_len);
            print_hex("Encrypted Message from Client: ", encrypted, enc_msg_len);

            //CLEAR BUFFER BEFORE decrypt()
            memset(buffer, 0, BUFFER_SIZE);
            decrypt(encrypted, buffer, enc_msg_len);
            printf("Decrypted Client Message: %s\n", buffer);
            SSL_write(ssl, "Message received", strlen("Message received"));
            break;
        } else {
            attempts++;
            const char *msg = (attempts < 2)
                ? "Wrong username or password. Try again"
                : "Authentication failed";
            SSL_write(ssl, msg, strlen(msg));
        }
    }

    // Close sockets
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_socket);
    close(server_fd);
    SSL_CTX_free(ctx);
    printf("Server shutting down...\n");

    return 0;
}
