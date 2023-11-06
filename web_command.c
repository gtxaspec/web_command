#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libwebsockets.h>
#include <cJSON.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#define MAX_PAYLOAD_SIZE 1024
#define MAX_HTTP_BODY_SIZE 4096	// Adjust as necessary for maximum expected POST body size
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
		.id = 0,
		.tx_packet_size = 0,
	},
	{
		.name = NULL, 
		.callback = NULL, 
		.per_session_data_size = 0, 
		.rx_buffer_size = 0,
		.id = 0,
		.tx_packet_size = 0,
	}
};

int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
	struct http_request_data *request_data = (struct http_request_data *)user;

	switch (reason) {
		case LWS_CALLBACK_HTTP_BODY: {
			size_t new_len = request_data->body_length + len;
			if (new_len < MAX_HTTP_BODY_SIZE) {
				memcpy(request_data->body + request_data->body_length, in, len);
				request_data->body_length = new_len;
			} else {
				// Handle overflow
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Payload too large");
				return 1; // Non-zero indicates error
			}
			break;
		}

		case LWS_CALLBACK_HTTP_BODY_COMPLETION: {
			// Null-terminate the body data
			request_data->body[request_data->body_length] = '\0';

			fprintf(stderr, "Received body: %s\n", request_data->body);

			// Process the command
			cJSON *json = cJSON_ParseWithOpts((char *)request_data->body, NULL, true);
			if (json == NULL) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Bad JSON");
				break;
			}

			cJSON *cmd = cJSON_GetObjectItemCaseSensitive(json, "command");
			if (!cJSON_IsString(cmd) || cmd->valuestring == NULL) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Invalid Command");
				cJSON_Delete(json);
				break;
			}

			fprintf(stderr, "Parsed command: %s\n", cmd->valuestring);

			// Open the configuration file
			char *config_data = NULL;
			FILE *config_file = fopen(CONFIG_FILE, "r");
			if (config_file != NULL) {
				fseek(config_file, 0, SEEK_END);
				long config_size = ftell(config_file);
				rewind(config_file);

				config_data = (char *)malloc(config_size + 1);
				if (config_data) {
					fread(config_data, config_size, 1, config_file);
					config_data[config_size] = '\0'; // Ensure null termination
				}
				fclose(config_file);
			}

			if (config_data == NULL) {
				lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Config File Error or Out of Memory");
				cJSON_Delete(json);
				break;
			}

			// Parse the configuration file
			cJSON *config_json = cJSON_Parse(config_data);
			free(config_data);

			if (config_json == NULL) {
				lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Config Parsing Error");
				cJSON_Delete(json);
				break;
			}

			// Map command from request to command in configuration
			cJSON *command_json = cJSON_GetObjectItemCaseSensitive(config_json, cmd->valuestring);
			if (command_json == NULL) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Command Not Found");
				cJSON_Delete(config_json);
				cJSON_Delete(json);
				break;
			}

			cJSON *command_item = cJSON_GetObjectItemCaseSensitive(command_json, "cmd");
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
				// Handle the error
				return 1;
			}
			break;
		}

		case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
			if (request_data) {
				memset(request_data, 0, sizeof(struct http_request_data));
			}
			break;

		default:
			break;
	}

	return 0;
}

void execute_command(const char *command) {
	fprintf(stderr, "Executing command: %s\n", command);
	pid_t pid = fork();
	if (pid == -1) {
		// Handle error in fork()
		fprintf(stderr, "Fork failed: %s\n", strerror(errno));
	} else if (pid > 0) {
		// Parent process, no need to wait for the first child.
		int status;
		waitpid(pid, &status, 0);	// Wait for the first child to exit
	} else {
		// First child process
		pid_t pid_inner = fork();
		if (pid_inner == -1) {
			// Handle error in second fork
			exit(EXIT_FAILURE);
		} else if (pid_inner > 0) {
			// Exit the first child process
			exit(EXIT_SUCCESS);
		} else {
			// Second child process
			execlp("sh", "sh", "-c", command, NULL);
			// If execlp() fails, exit the child process
			fprintf(stderr, "execlp failed to execute command: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
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
