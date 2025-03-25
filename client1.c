#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE] = {0};
    char username[50], password[50], message[BUFFER_SIZE];

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY; // Connect to localhost

    // Connect to server
    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Get username and password
    printf("Enter username: ");
    scanf("%s", username);
    printf("Enter password: ");
    scanf("%s", password);

    // Send username
    send(sock, username, strlen(username), 0);
    sleep(1); 

    // Send password
    send(sock, password, strlen(password), 0);

    // Receive response from server
    int bytes_received = read(sock, buffer, BUFFER_SIZE - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0'; 
        printf("Server: %s\n", buffer);
    } else {
        printf("No response from server.\n");
        close(sock);
        return 0;
    }

    // If authentication was successful, send a message to the server
    if (strcmp(buffer, "Authentication successful") == 0) {
        getchar(); 
        printf("Enter a message to send to the server: ");
        fgets(message, BUFFER_SIZE, stdin);
        message[strcspn(message, "\n")] = '\0'; 

        send(sock, message, strlen(message), 0);

        // Receive acknowledgment from server
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = read(sock, buffer, BUFFER_SIZE - 1);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Server: %s\n", buffer);
        }
    }

    // Close socket
    close(sock);
    return 0;
}
