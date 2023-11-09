#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libwebsockets.h>
#include <cJSON.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <time.h>

#define MAX_PAYLOAD_SIZE 1024
#define MAX_HTTP_BODY_SIZE 4096 // Adjust as necessary for our POST body size
#define CONFIG_FILE "test.config"
#define HTTP_PORT 8078
#define COMMAND_LIMIT 50
#define TIME_SPAN 30 // seconds

// HTTP POST request data structure
struct http_request_data {
	unsigned char body[MAX_HTTP_BODY_SIZE];
	size_t body_length;
};

// Rate limiting structure
struct command_rate_limiter {
	int count;
	time_t start_time;
} limiter = {0, 0};

// Function prototypes
int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);
bool load_configuration(const char *filepath, char **config_data);
bool is_command_allowed(const char *command, const cJSON *config_json);
bool check_rate_limit();

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

bool check_rate_limit() {
	time_t current_time = time(NULL);
	if (limiter.start_time == 0 || difftime(current_time, limiter.start_time) > TIME_SPAN) {
		// Reset rate limiter
		limiter.count = 1;
		limiter.start_time = current_time;
		return true;
	} else if (limiter.count < COMMAND_LIMIT) {
		// Increment the count and allow the command
		limiter.count++;
		return true;
	} else {
		// Rate limit exceeded
		return false;
	}
}

bool load_configuration(const char *filepath, char **config_data) {
	FILE *config_file = fopen(filepath, "r");
	if (config_file == NULL) {
		return false;
	}

	fseek(config_file, 0, SEEK_END);
	long config_size = ftell(config_file);
	rewind(config_file);

	*config_data = (char *)malloc(config_size + 1);
	if (*config_data == NULL) {
		fclose(config_file);
		return false;
	}

	size_t read_size = fread(*config_data, 1, config_size, config_file);
	if (read_size != (size_t)config_size) {
		free(*config_data);
		fclose(config_file);
		return false;
	}

	(*config_data)[config_size] = '\0'; // Ensure null termination
	fclose(config_file);
	return true;
}

char* execute_command(const char *command, bool return_output) {
	static char output[MAX_HTTP_BODY_SIZE]; // Buffer to store command output
	output[0] = '\0'; // Ensure it's a null-terminated string

	if (return_output) {
		FILE *pipe = popen(command, "r");
		if (pipe == NULL) {
			snprintf(output, sizeof(output), "Error: popen failed - %s", strerror(errno));
			return output;
		}

		char buffer[256];
		size_t output_len = 0;
		while (fgets(buffer, sizeof(buffer), pipe) != NULL && output_len < sizeof(output)) {
			strncat(output, buffer, sizeof(output) - output_len - 1);
			output_len += strlen(buffer);
		}

		pclose(pipe);
	} else {
		pid_t pid = fork();
		if (pid == -1) {
			snprintf(output, sizeof(output), "Error: fork failed - %s", strerror(errno));
		} else if (pid == 0) {
			// Child process
			execlp("sh", "sh", "-c", command, NULL);
			// If execlp() fails
			exit(EXIT_FAILURE);
		}
		// Parent process: assume the command executed successfully
		snprintf(output, sizeof(output), "Command executed");
	}

	return output;
}

int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
	struct http_request_data *request_data = (struct http_request_data *)user;

	switch (reason) {
		case LWS_CALLBACK_HTTP_BODY: {
			size_t new_len = request_data->body_length + len;
			if (new_len < MAX_HTTP_BODY_SIZE) {
				memcpy(request_data->body + request_data->body_length, in, len);
				request_data->body_length = new_len;
			} else {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Payload too large");
				return 1;
			}
			break;
		}

		case LWS_CALLBACK_HTTP_BODY_COMPLETION: {
			request_data->body[request_data->body_length] = '\0'; // Null-terminate the body data
			fprintf(stderr, "Received body: %s\n", request_data->body);
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

			if (!check_rate_limit()) {
				// If HTTP_STATUS_TOO_MANY_REQUESTS is not defined, define it or use an alternative
				#ifndef HTTP_STATUS_TOO_MANY_REQUESTS
				#define HTTP_STATUS_TOO_MANY_REQUESTS 429
				#endif

				lws_return_http_status(wsi, HTTP_STATUS_TOO_MANY_REQUESTS, "Rate limit exceeded");
				cJSON_Delete(json);
				break;
			}

			fprintf(stderr, "Parsed command: %s\n", cmd->valuestring);

			char *config_data = NULL;
			if (!load_configuration(CONFIG_FILE, &config_data)) {
				lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Config File Error");
				cJSON_Delete(json);
				break;
			}

			cJSON *config_json = cJSON_Parse(config_data);
			free(config_data);
			if (config_json == NULL) {
				lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Configuration Parse Error");
				cJSON_Delete(json);
				break;
			}

			cJSON *command_json = cJSON_GetObjectItemCaseSensitive(config_json, cmd->valuestring);
			if (command_json == NULL) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Command Not Found");
				cJSON_Delete(json);
				cJSON_Delete(config_json);
				break;
			}

			cJSON *command_item = cJSON_GetObjectItemCaseSensitive(command_json, "cmd");
			if (command_item == NULL || !cJSON_IsString(command_item)) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Invalid 'cmd' in configuration");
				cJSON_Delete(json);
				cJSON_Delete(config_json);
				break;
			}

			cJSON *return_output_item = cJSON_GetObjectItemCaseSensitive(command_json, "return_output");
			bool return_output = return_output_item != NULL && cJSON_IsTrue(return_output_item);

			char *command_output = execute_command(command_item->valuestring, return_output);
			size_t command_output_length = strlen(command_output);

			// Prepare HTTP headers
			unsigned char headers[MAX_HTTP_BODY_SIZE + LWS_PRE];
			unsigned char *p = &headers[LWS_PRE];
			unsigned char *end = &headers[sizeof(headers) - LWS_PRE];

			if (p < end) {
				p += snprintf((char *)p, end - p, "HTTP/1.1 200 OK\r\n");
				p += snprintf((char *)p, end - p, "Content-Type: text/plain\r\n");
				p += snprintf((char *)p, end - p, "Content-Length: %zu\r\n", command_output_length);
				p += snprintf((char *)p, end - p, "\r\n"); // End of HTTP headers
			}

			// Write HTTP headers
			int headers_length = lws_write(wsi, &headers[LWS_PRE], p - &headers[LWS_PRE], LWS_WRITE_HTTP_HEADERS);
			if (headers_length < 0) {
				// Handle failed write (e.g., log and cleanup)
				cJSON_Delete(json);
				cJSON_Delete(config_json);
				return -1;
			}

			// Write HTTP body
			int body_length = lws_write(wsi, (unsigned char *)command_output, command_output_length, LWS_WRITE_HTTP);
			if (body_length < 0) {
				// Handle failed write (e.g., log and cleanup)
				cJSON_Delete(json);
				cJSON_Delete(config_json);
				return -1;
			}

			cJSON_Delete(json);
			cJSON_Delete(config_json);

			if (lws_http_transaction_completed(wsi) != 0) {
				return -1;
			}

			break;
		}

		// ... other cases go here

		default:
			break;
	}

	return 0;
}

int main(void) {
	struct lws_context_creation_info info;
	memset(&info, 0, sizeof(info));
	info.port = HTTP_PORT;
	info.protocols = protocols;
	info.gid = -1;
	info.uid = -1;

	// Ignore SIGCHLD to prevent zombie processes
	signal(SIGCHLD, SIG_IGN);

	// Set resource limits
	struct rlimit rl;
	rl.rlim_cur = 1024;
	rl.rlim_max = 1024;
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
		fprintf(stderr, "Failed to set resource limits\n");
		return 1;
	}

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
