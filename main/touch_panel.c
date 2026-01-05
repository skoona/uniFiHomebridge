/*
 * touch_panel.c
*/
#include "driver/gpio.h"
#include "driver/i2c.h"
#include "esp_err.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_touch_ft6x36.h"
#include "esp_log.h"
#include "lvgl.h"
#include <stdio.h>

extern uint32_t panel_Hres;
extern uint32_t panel_Vres;
extern QueueHandle_t imageServiceQueue;
extern char *lastImageFile;
extern char *TAG; //  = "Touch";

extern esp_err_t fileList();

extern void skn_lvgl_touch_cb(lv_indev_t *drv, lv_indev_data_t *data);
extern void logMemoryStats(char *message);

void skn_touch_event_handler(lv_event_t *e)
{
	lv_point_t p;
	lv_indev_get_point(e->user_data, &p);
	int32_t screen_width = lv_obj_get_width(lv_scr_act());
	int32_t screen_height = lv_obj_get_height(lv_scr_act());

	printf("-->Event: X=%3.0ld\tY=%3.0ld\tScrnX=%3.0ld\tScrnY=%3.0ld\n", p.x, p.y, screen_width, screen_height);
	if (p.y > (screen_height / 2)) {
		printf("List all tasks: y=%ld\n", p.y);
		logMemoryStats("List all Task touch point.");
		fileList();
	} else if (p.x < (screen_width / 2)) {
		printf("File list touch point: x=%ld\n", p.x);
		fileList();
	} else {
		printf("Display prior image: x=%ld\n", p.x);
		fileList();
		xQueueSend(imageServiceQueue, lastImageFile, 0);
	}
}
void skn_touch_init() {
	ESP_LOGI("Touch", "Initialize I2C");

	const i2c_config_t i2c_conf = {
		.mode = I2C_MODE_MASTER,
		.sda_io_num = CONFIG_TOUCH_I2C_SDA_GPIO,
		.scl_io_num = CONFIG_TOUCH_I2C_SCK_GPIO,
		.sda_pullup_en = GPIO_PULLUP_ENABLE,
		.scl_pullup_en = GPIO_PULLUP_ENABLE,
		.master.clk_speed = CONFIG_I2C_MASTER_FREQUENCY,
	};
	// Initialize I2C
	ESP_ERROR_CHECK(i2c_param_config(CONFIG_I2C_MASTER_PORT_NUM, &i2c_conf));
	ESP_ERROR_CHECK(i2c_driver_install(CONFIG_I2C_MASTER_PORT_NUM, i2c_conf.mode, 0, 0, 0));

	esp_lcd_panel_io_i2c_config_t tp_io_config =
		ESP_LCD_TOUCH_IO_I2C_FT6x36_CONFIG();

	ESP_LOGI("Touch", "Initialize touch IO (I2C)");
	esp_lcd_panel_io_handle_t tp_io_handle = NULL;
	ESP_ERROR_CHECK(esp_lcd_new_panel_io_i2c(
		(esp_lcd_i2c_bus_handle_t)CONFIG_I2C_MASTER_PORT_NUM, &tp_io_config, &tp_io_handle));

	esp_lcd_touch_config_t tp_cfg = {
		.x_max = panel_Hres,
		.y_max = panel_Vres,
		.rst_gpio_num = -1,
		.int_gpio_num = -1,
		.levels =
			{
				.reset = 0,
				.interrupt = 0,
			},
		.flags =
			{
				.swap_xy = 1, // rotated
				.mirror_x = 1,
				.mirror_y = 0,
			},
	};

	/* Initialize touch */
	ESP_LOGI("Touch", "Initialize touch controller FT6x36");
	esp_lcd_touch_handle_t tp;
	ESP_ERROR_CHECK(esp_lcd_touch_new_i2c_ft6x36(tp_io_handle, &tp_cfg, &tp));

	/* Above Config has V/H swapped and flags set
		esp_lcd_touch_set_swap_xy(tp,true);
		esp_lcd_touch_set_mirror_x(tp, true);
		esp_lcd_touch_set_mirror_y(tp, false);
	*/

	/*Create an input device for touch handling*/
	lv_indev_t *indev;
	indev = lv_indev_create();
	lv_indev_set_type(indev, LV_INDEV_TYPE_POINTER);
	lv_indev_set_read_cb(indev, skn_lvgl_touch_cb);
	lv_indev_set_user_data(indev, tp);
 	lv_indev_add_event_cb(indev, skn_touch_event_handler, LV_EVENT_CLICKED, indev);

}
