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
    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE] = {0};
    unsigned char encrypted_user[BUFFER_SIZE], encrypted_pass[BUFFER_SIZE];
    char username[50], password[50], message[BUFFER_SIZE];

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
        int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0'; 
            printf("Server: %s\n", buffer);
        } else {
            printf("No response from server.\n");
            close(sock);
            return 0;
        }

        // If authentication was successful, send a message to the server
        if (strcmp((char*)buffer, "Authentication successful") == 0) {
            getchar();
            printf("Enter a message to send to the server: ");
            fgets(message, BUFFER_SIZE, stdin);
            message[strcspn(message, "\n")] = '\0';
            int msg_len = strlen(message);
            unsigned char encrypted_msg[BUFFER_SIZE];
            encrypt((unsigned char*)message, encrypted_msg, msg_len);
            int enc_msg_len = ((msg_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

            // Send length then encrypted message
            SSL_write(ssl, &msg_len, sizeof(int));
            SSL_write(ssl, encrypted_msg, enc_msg_len);

            // Receive acknowledgment from server
            memset(buffer, 0, BUFFER_SIZE);
            bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                printf("Server: %s\n", buffer);
            }
            break;
        } else {
            attempts++;
            if (attempts == 2) {
                printf("Too many failed attempts. Closing connection.\n");
            }
        }
    }
    

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}

