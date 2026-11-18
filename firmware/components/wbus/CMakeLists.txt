# Pure logic: the object registry, the argument policy tables and the reply sink.
# No Arduino and no esp_* -- the console injects a Serial-backed sink, so the same
# object tables can serve the LVGL screen or a socket without dragging them in.
idf_component_register(SRCS "wbus.cpp"
                       INCLUDE_DIRS "include")
