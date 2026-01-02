idf_component_register(SRCS "wifi_network.c"
                    REQUIRES nvs_flash esp_netif esp_wifi
                    INCLUDE_DIRS "include")
