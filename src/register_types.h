#ifndef WEBSOCKET_SERVER_REGISTER_TYPES_H
#define WEBSOCKET_SERVER_REGISTER_TYPES_H

#include <godot_cpp/core/class_db.hpp>

using namespace godot;

void initialize_websocket_server_module(ModuleInitializationLevel p_level);
void uninitialize_websocket_server_module(ModuleInitializationLevel p_level);

#endif // WEBSOCKET_SERVER_REGISTER_TYPES_H