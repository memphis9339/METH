#include <stdio.h>
#include <meth.h>
#include <internal/meth_internal.h>
#include <string.h>

int main(int argc, char* argv[])
{
    if (argc > 1) {
        if (strcmp(argv[1], "client") == 0) 
        {
            printf("connecting to 127.0.0.1:9339..\n");
            meth_connection* conn = meth_secure_connect("127.0.0.1", 9339);
            if (!conn) {
                printf("cannot connect");
                return 0;
            }
            
            printf("connect & key exchange succses\n");
            printf("shared key:\n");
            for (int i = 0; i < sizeof(conn->shared_key); i++) {
                printf("%02x", conn->shared_key[i]); 
            }

            printf("\n");
            const char* data = "blablabla";

            ssize_t sent = meth_secure_send(conn, data, strlen(data));
            printf("wrote %zu bytes", sent);

            return 0;
        }
    }
    

    meth_server* server = meth_create_server(9339);
    

    if (!server || server->fd < 0) {
        perror("meth_listen failed");
        return 1;
    }
    printf("listening on %d fd\n", server->fd);
    while (1) 
    {
        meth_connection* client = meth_accept(server);
        if (client != NULL && client->fd != -1) {
            meth_buffer* res = meth_secure_recv(client);
            printf("received %d bytes\n", res->len);
        }
    }
    
    return 0;
}