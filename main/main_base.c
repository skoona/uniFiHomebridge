/* MQTT (over TCP) Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <dirent.h>
#include <inttypes.h>
#include "driver/gpio.h"
#include "driver/ledc.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "mbedtls/base64.h"
#include "cJSON.h"
#include "wifi_network.h"
#include "mqtt_client.h"

#define BUZZER_GPIO 20
#define LEDC_TIMER LEDC_TIMER_0
#define LEDC_MODE LEDC_LOW_SPEED_MODE
#define LEDC_CHANNEL LEDC_CHANNEL_0
#define LEDC_DUTY_RES LEDC_TIMER_13_BIT // 8191
#define LEDC_DUTY (4095)                // 50% duty cycle (4095 out of 8191)
#define LEDC_FREQUENCY (600)            // Hz tone
#define BEEP_DURATION_MS 500
#define IMAGE_HEADER_BYTES 23

static const char *TAG = "main";

void logMemoryStats(char *message)
{
    ESP_LOGI(TAG, "[APP] %s...", message);
    ESP_LOGI(TAG, "[APP]       IDF version: %s", esp_get_idf_version());
    ESP_LOGI(TAG, "[APP]       Free memory: %" PRIu32 " bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "Internal free heap size: %ld bytes", esp_get_free_internal_heap_size());
    ESP_LOGI(TAG, "PSRAM    free heap size: %ld bytes", esp_get_free_heap_size() - esp_get_free_internal_heap_size());
    ESP_LOGI(TAG, "Total    free heap size: %ld bytes", esp_get_free_heap_size());
}
static void log_error_if_nonzero(const char *message, int error_code)
{
    if (error_code != 0)
    {
        ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
    }
}
esp_err_t skn_beep_init()
{
    ESP_LOGI(TAG, "skn_beep_init(): Initializing");
    // Configure LEDC Timer
    ledc_timer_config_t timer_conf = {
        .speed_mode = LEDC_MODE,
        .timer_num = LEDC_TIMER,
        .duty_resolution = LEDC_DUTY_RES,
        .freq_hz = LEDC_FREQUENCY,
        .clk_cfg = LEDC_AUTO_CLK,
    };
    ledc_timer_config(&timer_conf);

    // Configure LEDC Channel
    ledc_channel_config_t channel_conf = {
        .gpio_num = BUZZER_GPIO,
        .speed_mode = LEDC_MODE,
        .channel = LEDC_CHANNEL,
        .intr_type = LEDC_INTR_DISABLE,
        .timer_sel = LEDC_TIMER,
        .duty = 0, // Start with buzzer off
    };
    return ledc_channel_config(&channel_conf);
}
void skn_beep(uint32_t duration_ms)
{
    // Set the duty cycle and update the channel to start the sound
    ledc_set_duty(LEDC_MODE, LEDC_CHANNEL, LEDC_DUTY);
    ledc_update_duty(LEDC_MODE, LEDC_CHANNEL);

    // Wait for the beep duration
    vTaskDelay(pdMS_TO_TICKS(duration_ms));

    // Stop the sound (set duty to 0)
    ledc_set_duty(LEDC_MODE, LEDC_CHANNEL, 0);
    ledc_update_duty(LEDC_MODE, LEDC_CHANNEL);
}
esp_err_t fileList()
{
    /* Get file name in storage */
    struct dirent *p_dirent = NULL;
    struct stat st;
    ESP_LOGI(TAG, "fileList(): Proceeding...");

    DIR *p_dir_stream = opendir("/spiffs");
    if (p_dir_stream == NULL)
    {
        ESP_LOGE(TAG, "Failed to open mount: %s", "/spiffs");
        return ESP_FAIL;
    }

    char files[256] = {"/spiffs/"};

    /* Scan files in storage */
    while (true)
    {
        p_dirent = readdir(p_dir_stream);
        if (NULL != p_dirent)
        {
            strcpy(files, "/spiffs/");
            strcat(files, p_dirent->d_name);
            if (stat(files, &st) == 0)
            {
                ESP_LOGI(TAG, "Filename: [%d] %s", st.st_size,
                         p_dirent->d_name);
            }
            else
            {
                ESP_LOGI(TAG, "Filename: %s", p_dirent->d_name);
            }
        }
        else
        {
            closedir(p_dir_stream);
            break;
        }
    }
    return ESP_OK;
}
esp_err_t skn_spiffs_mount(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = "storage",
        .max_files = 12,
        .format_if_mount_failed = false,
    };

    esp_err_t ret_val = esp_vfs_spiffs_register(&conf);

    ESP_ERROR_CHECK(ret_val);

    size_t total = 0, used = 0;
    ret_val = esp_spiffs_info(conf.partition_label, &total, &used);
    if (ret_val != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s)",
                 esp_err_to_name(ret_val));
    } else {
        ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    }

    return ret_val;
}
esp_err_t skn_spiffs_unmount(void)
{
    return esp_vfs_spiffs_unregister("storage");
}

esp_err_t writeBinaryImageFile(char *path, void *buffer, int bufLen) {

    // uint written = 0;
    // int event_file = 0;
    ESP_LOGI("writeBinaryImageFile()", "Proceeding with: %s", path);

    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open file for writing");
        return ESP_FAIL;
    }
    size_t bytes_written = fwrite(buffer, 1, bufLen, f);
    if (bytes_written != bufLen) {
        ESP_LOGE(TAG, "Failed to write all binary data. Wrote %d of %d bytes", bytes_written, bufLen);
    } else {
        ESP_LOGI(TAG, "Wrote %d bytes successfully", bytes_written);
    }
    fclose(f);
/*    // #include <stdio.h> not working, open()/close() are missing

    event_file = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (event_file == -1)
    {
        ESP_LOGE("writeBinaryImageFile()", "Failed to open %s file for writing", path);
        return ESP_FAIL;
    }
    else
    {
        written = write(event_file, buffer, bufLen);
        close(event_file);
        ESP_LOGI("writeBinaryImageFile()", "File written, name: %s, bytes: %d", path, written);
    }
*/
    // Create image
    // Notify processor of written filename, queue or event

    return ESP_OK;
}
esp_err_t writeBase64Buffer(char *path, const unsigned char *input_buffer, int data_len)
{
    unsigned char *output_buffer;
    size_t output_len;

    // Allocate memory for the output buffer
    output_len = ((data_len + 3) / 3) * 4 + 1;
    output_buffer = (unsigned char *)calloc(output_len, sizeof(unsigned char));
    if (output_buffer == NULL)
    {
        ESP_LOGE("writeBase64Buffer()", "Failed to allocate [%d:%d] bytes for base64 output buffer for: %s", data_len, output_len, path);
        return ESP_FAIL;
    }
    // 'data:image/jpeg;base64,' = 23 bytes
    int ret = mbedtls_base64_decode(output_buffer, output_len, &output_len, input_buffer, data_len);
    if (ret == 0)
    {
        // Decoding successful.
        ret = writeBinaryImageFile(path, output_buffer, output_len);
    }
    else
    {
        ESP_LOGE("writeBase64Buffer()", "Failed to decode base64 contents for: %s", path);
        ret = ESP_FAIL;
    }
    free(output_buffer); // Clean up memory
    return ret;
}
esp_err_t prettyPrintJSON(char * content, int contentLen) {
    cJSON *json;
    char *json_string;

    json = cJSON_Parse(content);
    if (json == NULL)
    {
        ESP_LOGE("skn_parse_msg()", "cJSON_Parse Failed: [L=%d]%s", contentLen, cJSON_GetErrorPtr());
        return ESP_FAIL;
    }

    json_string = cJSON_Print(json);
    if (json_string == NULL)
    {
        ESP_LOGE("skn_parse_msg()", "cJSON_Print Failed: [L=%d]\n", contentLen);
        cJSON_Delete(json);
        return ESP_FAIL;
    }

    int json_len = strlen(json_string);
    printf("\n%.*s\r\n", json_len, json_string);

    cJSON_free(json_string);
    cJSON_Delete(json);    

    return ESP_OK;
}

esp_err_t skn_parse_event_msg(esp_mqtt_event_handle_t event) {
    static char path[32] = {0};
    static char device[16] = {0};
    static char topic[128] = {0};
    static bool imageTransaction = false;
    static bool jsonTransaction = false;
    static char *content = NULL;
    static int contentLen = 0;

    ESP_LOGI("skn_parse_msg()", "Topic=%.*s\tLen=%d\tTotal=%d\tOffset=%d", event->topic_len, event->topic, event->data_len, event->total_data_len, event->current_data_offset);
    if ((event->data == NULL) || (event->data_len == 0)) {
        ESP_LOGE("skn_parse_msg()", "Segment handler -> Event has no data");
        return ESP_OK;
    }

    printf("%.*s:\t", event->topic_len, event->topic);

    if (imageTransaction || jsonTransaction) {
        if (content == NULL)
        {
            ESP_LOGE("skn_parse_msg()", "Segment handler triggered out of order");
            imageTransaction = false;
            jsonTransaction = false;
            contentLen = 0;
            return ESP_OK;
        }

        ESP_LOGI("skn_parse_msg()", "CONTINUE: Segment handler processing for %s from %s", device, topic);

        if (contentLen < event->total_data_len) {
            memcpy(&content[event->current_data_offset], event->data, event->data_len);
            contentLen += event->data_len;            
        }
        if (contentLen == event->total_data_len) {
            
            if (imageTransaction) {
                ESP_LOGI("skn_parse_msg()", "END: IMAGE --> Segment handler completed for %s from %s", path, topic);
                writeBase64Buffer(path, (const unsigned char *)&content[IMAGE_HEADER_BYTES], contentLen-IMAGE_HEADER_BYTES);
                imageTransaction = false;
                fileList();
            } else if (jsonTransaction) {
                ESP_LOGI("skn_parse_msg()", "END: JSON --> Segment handler completed for %s from %s", device, topic);
                prettyPrintJSON(content, contentLen);
                jsonTransaction = false;
            }
            free(content);
            contentLen = 0;
        }

    } else if ((event->data_len >= 5) && (strncmp(event->data, "data:", 5) == 0 )) {
        // current_data_offset and total_data_len
        // "/spiffs/<device>.jpg"
        // 'unifi/protect/<device>/snapshot' --> 'unifi/protect/+/snapshot'
        //  012345678901234
        strncpy(topic, event->topic, event->topic_len);
        topic[event->topic_len] = '\0';
        strncpy(device, &event->topic[14], 12);
        device[12] = '\0';

        sprintf(path,"/spiffs/%s.jpg", device);
        ESP_LOGI("skn_parse_msg()", "Generating image file path: %s", path);

        if (event->data_len != event->total_data_len) {
            content = calloc(event->total_data_len+4, sizeof(uint8_t));
            if (content != NULL) {
                imageTransaction = true;
                memcpy(&content[event->current_data_offset], event->data, event->data_len);
                contentLen = event->data_len;
                ESP_LOGI("skn_parse_msg()", "START: IMAGE -> Segment handler triggered for %s from %s", path, topic);
                return ESP_OK;
            } else {
                ESP_LOGE("skn_parse_msg()", "Cannot allocate %d bytes for segmented buffer", event->total_data_len);
                imageTransaction = false;
                return ESP_FAIL;
            }
        } 

        writeBase64Buffer(path, (const unsigned char *)&event->data[IMAGE_HEADER_BYTES], event->data_len-IMAGE_HEADER_BYTES);
        fileList();

    } else if ( event->data[0] == '{') {
        strncpy(topic, event->topic, event->topic_len);
        topic[event->topic_len] = '\0';
        strncpy(device, &event->topic[14], 12);
        device[12] = '\0';

        if (event->data_len != event->total_data_len) {
            content = calloc(event->total_data_len + 4, sizeof(uint8_t));
            if (content != NULL) {
                jsonTransaction = true;
                memcpy(&content[event->current_data_offset], event->data, event->data_len);
                contentLen = event->data_len;
                ESP_LOGI("skn_parse_msg()", "START: JSON -> Segment handler triggered for %s from %s", device, topic);
                return ESP_OK;
            } else {
                ESP_LOGE("skn_parse_msg()", "Cannot allocate %d bytes for segmented buffer", event->total_data_len);
                jsonTransaction = false;
                contentLen = 0;
                return ESP_FAIL;
            }
        }

        prettyPrintJSON(event->data, event->data_len);

    } else {
        printf("%.*s\r\n", event->data_len, event->data);
    }

    return ESP_OK;
}

/*
 * MQTT topic/data values are present on first receipt
 * - topic is not provided on segmented message
 * - Will process three message patterns
 * - - String data from subscription: "unifi/protect/+/motion"
 * - - JSON data from subscription: "unifi/protect/+/motion"
 * - - IMAGE/JPEG data from subscription: "unifi/protect/+/snapshot"
 */
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%" PRIi32 "", base, event_id);
    esp_mqtt_event_handle_t event = event_data;
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;
    switch ((esp_mqtt_event_id_t)event_id)
    {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
        msg_id = esp_mqtt_client_publish(client, CONFIG_BROKER_NETWORK_BROADCAST, "Elecrow32-02 Online", 0, 1, 0);
        ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);

        msg_id = esp_mqtt_client_subscribe(client, CONFIG_BROKER_NETWORK_TOPIC, 0); 
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d, topic=%s", msg_id, CONFIG_BROKER_NETWORK_TOPIC);

        msg_id = esp_mqtt_client_subscribe(client, "unifi/protect/+/motion", 0);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d, topic=%s", msg_id, "unifi/protect/+/motion");
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
        break;
    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT_EVENT_DATA");
        skn_parse_event_msg(event);
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
        if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT)
        {
            log_error_if_nonzero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
            log_error_if_nonzero("reported from tls stack", event->error_handle->esp_tls_stack_err);
            log_error_if_nonzero("captured as transport's socket errno", event->error_handle->esp_transport_sock_errno);
            ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));
        }
        break;
    default:
        ESP_LOGI(TAG, "Other event id:%d", event->event_id);
        break;
    }
}
static void mqtt_app_start(void)
{
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = CONFIG_BROKER_URL,
        .session.protocol_ver = MQTT_PROTOCOL_V_3_1_1,
        .network.disable_auto_reconnect = false,
        .credentials.username = CONFIG_BROKER_USERID,
        .credentials.authentication.password = CONFIG_BROKER_PASSWORD,
        .session.last_will.topic = CONFIG_BROKER_NETWORK_LWTP,
        .session.last_will.msg = "Going offfline",
        .session.last_will.msg_len = 14,
        .session.last_will.qos = 1,
        .session.last_will.retain = true,
        // .buffer.size = (8 * 1024),
        // .buffer.out_size = (2 * 1024),
    };
    // current_data_offset and total_data_len
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);
}
void app_main(void) {
    logMemoryStats("Startup Begining...");

    esp_log_level_set("*", ESP_LOG_INFO);
    esp_log_level_set("mqtt_client", ESP_LOG_VERBOSE);
    esp_log_level_set("transport_base", ESP_LOG_VERBOSE);
    esp_log_level_set("esp-tls", ESP_LOG_VERBOSE);
    esp_log_level_set("transport", ESP_LOG_VERBOSE);
    esp_log_level_set("wifi", ESP_LOG_ERROR);
    
    ESP_ERROR_CHECK(skn_spiffs_mount());
    ESP_ERROR_CHECK(skn_beep_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(skn_wifi_service());
        
    mqtt_app_start();

    fileList();
    skn_beep(BEEP_DURATION_MS);

    logMemoryStats("Startup Complete...");
}