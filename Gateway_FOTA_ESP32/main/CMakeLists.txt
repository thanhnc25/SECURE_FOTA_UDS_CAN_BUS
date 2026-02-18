set(UI_DIR "ui")

# Lấy toàn bộ file .c do SquareLine xuất ra
set(UI_SRCS
    "${UI_DIR}/ui.c"
    "${UI_DIR}/ui_events.c"
    "${UI_DIR}/ui_helpers.c"
    "${UI_DIR}/screens/ui_Screen1.c"
    "${UI_DIR}/screens/ui_Screen2.c"
    "${UI_DIR}/screens/ui_Screen3.c"
    "${UI_DIR}/screens/ui_Screen4.c"
    "${UI_DIR}/screens/ui_Screen5.c"
    "${UI_DIR}/screens/ui_Screen6.c"
    "${UI_DIR}/screens/ui_Screen7.c"
    "${UI_DIR}/screens/ui_Screen8.c"
    "${UI_DIR}/components/ui_comp.c"
    "${UI_DIR}/components/ui_comp_hook.c"
    "${UI_DIR}/components/ui_comp_ethernet.c"
    "${UI_DIR}/components/ui_comp_time1.c"
    "${UI_DIR}/fonts/ui_font_FontAwesome.c"
    "${UI_DIR}/fonts/ui_font_ROBOTO_24.c"
    "${UI_DIR}/fonts/ui_font_ROBOTO_46.c"
    "${UI_DIR}/images/ui_img_1098943249.c"
    "${UI_DIR}/images/ui_img_1473374238.c"
    "${UI_DIR}/images/ui_img_1572108927.c"
    "${UI_DIR}/images/ui_img_1626744017.c"
    "${UI_DIR}/images/ui_img_1940066473.c"
    "${UI_DIR}/images/ui_img_692277852.c"
    "${UI_DIR}/images/ui_img_894706582.c"
)

idf_component_register(
    SRCS
        "main.cpp"
        "src/fota_manager.cpp"
        "src/udp_discovery.cpp"
        "src/tcp_fota_client.cpp"
        "src/fota_security.cpp"
        "src/ethernet_lan8720.cpp"
        "src/wifi_station.cpp"
        "src/uds_client.cpp"
        "src/version_checker.cpp"
        "src/auto_update_task.cpp"
        "src/lcd_driver.cpp"
        "src/time_sync.cpp"
        "src/ui_manager.cpp"
        ${UI_SRCS}
    INCLUDE_DIRS "." "include" "${UI_DIR}"
    REQUIRES 
        can_driver 
        cantp 
        esp_wifi 
        esp_event 
        esp_netif 
        esp_eth 
        nvs_flash 
        lwip 
        mbedtls 
        esp_http_client 
        json 
        esp-tls
        lvgl
        esp_lcd
        esp_lcd_ili9341
        esp_lcd_touch
        esp_lcd_touch_xpt2046
    PRIV_REQUIRES esp_timer
)
