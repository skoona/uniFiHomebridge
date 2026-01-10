idf_component_register(SRCS "main.c" "service_mqtt.c" "rgb_panel.c" "page_intro.c"
                    REQUIRES wifi_network
                    PRIV_REQUIRES mqtt spiffs esp_timer esp_driver_ledc esp_driver_gpio esp_driver_i2c esp_psram
                    INCLUDE_DIRS ".")
