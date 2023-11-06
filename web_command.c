#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libwebsockets.h>
#include <cJSON.h>

#define MAX_PAYLOAD_SIZE 1024
#define MAX_HTTP_BODY_SIZE 4096  // Adjust as necessary for maximum expected POST body size
#define CONFIG_FILE "test.config"
#define HTTP_PORT 8078

// HTTP POST request data structure
struct http_request_data {
    unsigned char body[MAX_HTTP_BODY_SIZE];
    size_t body_length;
};

// Function prototypes
int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);
void execute_command(const char *command);

// Updated protocols array with explicit zero initializers for all fields
static const struct lws_protocols protocols[] = {
    {
        .name = "http-only",
        .callback = callback_http,
        .per_session_data_size = sizeof(struct http_request_data),
        .rx_buffer_size = MAX_PAYLOAD_SIZE,
        // Explicitly initialize all other fields to zero.
        .id = 0,
        .tx_packet_size = 0,
        // Add any other fields with designated initializers here, set to 0 or appropriate default values
    },
    // The terminator is fully initialized to zero with designated initializers
    { 
        .name = NULL, 
        .callback = NULL, 
        .per_session_data_size = 0, 
        .rx_buffer_size = 0,
        .id = 0,
        .tx_packet_size = 0,
        // Initialize any other fields here
    }
};

// HTTP/WebSocket callback function
int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    struct http_request_data *request_data = (struct http_request_data *)user;

    switch (reason) {
        case LWS_CALLBACK_HTTP_BODY: {
            // Accumulate HTTP body data
            if (request_data->body_length + len < MAX_HTTP_BODY_SIZE) {
                memcpy(request_data->body + request_data->body_length, in, len);
                request_data->body_length += len;
            }
            break;
        }

        case LWS_CALLBACK_HTTP_BODY_COMPLETION: {
            // Null-terminate the body data
            request_data->body[request_data->body_length] = '\0';

            // Process the command
            cJSON *json = cJSON_Parse((char *)request_data->body);
            if (json == NULL) {
                lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Bad JSON");
                break;
            }

            cJSON *cmd = cJSON_GetObjectItem(json, "command");
            if (cmd == NULL || !cJSON_IsString(cmd)) {
                lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Invalid Command");
                cJSON_Delete(json);
                break;
            }

            // Load the configuration file
            FILE *config_file = fopen(CONFIG_FILE, "r");
            if (config_file == NULL) {
                lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Config File Error");
                cJSON_Delete(json);
                break;
            }

            fseek(config_file, 0, SEEK_END);
            long config_size = ftell(config_file);
            rewind(config_file);

            char *config_data = malloc(config_size + 1);
            fread(config_data, config_size, 1, config_file);
            fclose(config_file);
            config_data[config_size] = '\0';

            // Parse the configuration file
            cJSON *config_json = cJSON_Parse(config_data);
            free(config_data);

            if (config_json == NULL) {
                lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Config Parsing Error");
                cJSON_Delete(json);
                break;
            }

            // Map command from request to command in configuration
            cJSON *command_json = cJSON_GetObjectItem(config_json, cmd->valuestring);
            if (command_json == NULL) {
                lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Command Not Found");
                cJSON_Delete(config_json);
                cJSON_Delete(json);
                break;
            }

            cJSON *command_item = cJSON_GetObjectItem(command_json, "cmd");
            if (command_item == NULL || !cJSON_IsString(command_item)) {
                lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Invalid 'cmd'");
                cJSON_Delete(config_json);
                cJSON_Delete(json);
                break;
            }

            // Execute the command
            execute_command(command_item->valuestring);

            // Respond to HTTP request
            lws_return_http_status(wsi, HTTP_STATUS_OK, "Command Executed");

            cJSON_Delete(config_json);
            cJSON_Delete(json);

            // Inform lws to close the HTTP connection after the response is sent
	    if (lws_http_transaction_completed(wsi) != 0) {
               // handle the error
            }
            break;
        }

        case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
            // Cleanup the allocated memory when the HTTP context is dropped
            if (request_data) {
                memset(request_data, 0, sizeof(struct http_request_data));
            }
            break;

        default:
            break;
    }

    return 0;
}

// Function to execute the shell command
/* void execute_command(const char *command) {
    // Use system() for simplicity, though a more secure alternative should be used
    int ret = system(command);
    if (ret != 0) {
        // Handle system call error
        fprintf(stderr, "Command execution failed with status: %d\n", ret);
    }
}*/

// Function to execute the shell command asynchronously
void execute_command(const char *command) {
    pid_t pid = fork();
    if (pid == -1) {
        // Handle error in fork()
    } else if (pid > 0) {
        // This is the parent process, which can immediately return
        // Optionally, you can use waitpid() with WNOHANG to avoid zombie processes
    } else {
        // This is the child process
        // Use execlp() or a similar function to replace the child process with the command
        execlp("sh", "sh", "-c", command, NULL);
        // If execlp() fails, exit the child process
        exit(EXIT_FAILURE);
    }
}


int main(void) {
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = HTTP_PORT;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;

    struct lws_context *context = lws_create_context(&info);
    if (context == NULL) {
        fprintf(stderr, "lws init failed\n");
        return 1;
    }

    // Server loop
    while (1) {
        lws_service(context, 1000);
    }

    lws_context_destroy(context);
    return 0;
}
