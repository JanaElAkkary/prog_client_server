#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

const char *valid_users[2][2] = {
    {"jana", "jana123"},
    {"adham", "adham123"}
};

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
    char username[BUFFER_SIZE], password[BUFFER_SIZE], buffer[BUFFER_SIZE];

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

    // Receive username
    memset(username, 0, BUFFER_SIZE);
    int bytes_received = recv(new_socket, username, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        perror("Failed to receive username");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    username[bytes_received] = '\0';

    // Receive password
    memset(password, 0, BUFFER_SIZE);
    bytes_received = recv(new_socket, password, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        perror("Failed to receive password");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    password[bytes_received] = '\0'; 

    printf("Received credentials - Username: %s, Password: %s\n", username, password);

    // Authenticate user
    if (authenticate(username, password)) {
        send(new_socket, "Authentication successful", strlen("Authentication successful"), 0);

        // Wait for client message after successful authentication
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recv(new_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Client message: %s\n", buffer);
            send(new_socket, "Message received", strlen("Message received"), 0);
        }
        
    } else {
        send(new_socket, "Authentication failed", strlen("Authentication failed"), 0);
    }

    // Close sockets
    close(new_socket);
    close(server_fd);
    printf("Server shutting down...\n");

    return 0;
}
