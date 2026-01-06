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
#include "esp_log.h"
#include "esp_spiffs.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "mbedtls/base64.h"
#include "cJSON.h"
#include "mqtt_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/projdefs.h"

#define BEEP_DURATION_MS 500
#define IMAGE_HEADER_BYTES 23

extern esp_err_t fileList();
extern void skn_beep(uint32_t duration_ms);

void log_error_if_nonzero(const char *message, int error_code)
{
    if (error_code != 0)
    {
        ESP_LOGE("MqttService", "Last error %s: 0x%x", message, error_code);
    }
}

esp_err_t writeBinaryImageFile(char *path, void *buffer, int bufLen)
{
    esp_err_t ret = ESP_OK;

    ESP_LOGI("writeBinaryImageFile()", "Proceeding with: %s", path);

    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        ESP_LOGE("MqttService", "Failed to open file for writing --> %s", path);
        return ESP_FAIL;
    }
    size_t bytes_written = fwrite(buffer, 1, bufLen, f);
    if (bytes_written != bufLen) {
        ESP_LOGE("MqttService", "Failed to write all binary data. Wrote %d of %d bytes", bytes_written, bufLen);
        ret = ESP_FAIL;
    } else {
        ESP_LOGI("MqttService", "Wrote %d bytes successfully", bytes_written);
    }
    fclose(f);

    return ret;
}
esp_err_t writeBase64Buffer(char *path, const unsigned char *input_buffer, int data_len, QueueHandle_t ImageQueue)
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
        if (ret == ESP_OK) {
            // xQueueSend(imageServiceQueue, path, 0);
            xQueueSend(ImageQueue, path, 0);
        }
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

esp_err_t skn_parse_event_msg(esp_mqtt_event_handle_t event, QueueHandle_t ImageQueue) {
    static char path[128] = {0};
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
                writeBase64Buffer(path, (const unsigned char *)&content[IMAGE_HEADER_BYTES], contentLen - IMAGE_HEADER_BYTES, ImageQueue);
                imageTransaction = false;
                fileList();
            } else if (jsonTransaction) {
                ESP_LOGI("skn_parse_msg()", "END: JSON --> Segment handler completed for %s from %s", device, topic);
                prettyPrintJSON(content, contentLen);
                jsonTransaction = false;
            }
            free(content);
            contentLen = 0;
            skn_beep(BEEP_DURATION_MS);
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

        writeBase64Buffer(path, (const unsigned char *)&event->data[IMAGE_HEADER_BYTES], event->data_len - IMAGE_HEADER_BYTES,  ImageQueue);
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
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    ESP_LOGD("MqttService", "Event dispatched from event loop base=%s, event_id=%" PRIi32 "", base, event_id);
    esp_mqtt_event_handle_t event = event_data;
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;
    switch ((esp_mqtt_event_id_t)event_id)
    {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI("MqttService", "MQTT_EVENT_CONNECTED");
        msg_id = esp_mqtt_client_publish(client, CONFIG_BROKER_NETWORK_BROADCAST, "Elecrow32-02 Online", 0, 1, 0);
        ESP_LOGI("MqttService", "sent publish successful, msg_id=%d", msg_id);

        msg_id = esp_mqtt_client_subscribe(client, CONFIG_BROKER_NETWORK_TOPIC, 0); 
        ESP_LOGI("MqttService", "sent subscribe successful, msg_id=%d, topic=%s", msg_id, CONFIG_BROKER_NETWORK_TOPIC);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI("MqttService", "MQTT_EVENT_DISCONNECTED");
        break;
    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI("MqttService", "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI("MqttService", "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI("MqttService", "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI("MqttService", "MQTT_EVENT_DATA");
        skn_parse_event_msg(event, (QueueHandle_t)handler_args);
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI("MqttService", "MQTT_EVENT_ERROR");
        if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT)
        {
            log_error_if_nonzero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
            log_error_if_nonzero("reported from tls stack", event->error_handle->esp_tls_stack_err);
            log_error_if_nonzero("captured as transport's socket errno", event->error_handle->esp_transport_sock_errno);
            ESP_LOGI("MqttService", "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));
        }
        break;
    default:
        ESP_LOGI("MqttService", "Other event id:%d", event->event_id);
        break;
    }
}

/*
 * MQTT internal config determines the CoreID it runs on: see sdkConfig
*/
esp_err_t skn_mqtt_service(QueueHandle_t ImageQueue) {
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
        // .buffer.size = (4 * 1024),
        // .buffer.out_size = (1 * 1024),
    };
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, ImageQueue);
    return esp_mqtt_client_start(client);
}
