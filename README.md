# WebSocketServer GDExtension

A high-performance WebSocket server class for Godot 4


## Features

- **Full WebSocket Protocol Support** - Handles text, binary, and control (ping, pong, close) frames
- **Thread-Safe Architecture** - Server operations run on a background thread with signal-based communication
- **WebSocket Frame Buffering** - Handles TCP fragmentation and partial WebSocket frames
- **Multiple Client Support** - Manages multiple simultaneous WebSocket connections
- **Client Validation** - WebSocket handshake with basic SHA-1 key validation
- **Message Unmasking** - Handles masking protocol for client messages


## Installation

1. Download the latest release from the [Releases page](../../releases)
2. Extract the `addons` folder to the root folder of your project
3. The extension will be loaded automatically when you restart Godot


## Quick Start

```gdscript
extends Node

var server = WebSocketServer.new()

func _ready():
    # Connect to server signals
    server.client_connected.connect(_on_client_connected)
    server.client_disconnected.connect(_on_client_disconnected)
    server.message_received.connect(_on_message_received)
    server.data_received.connect(_on_data_received)
    
    # Start server on port 8080
    if server.start(8080, "0.0.0.0"):
        print("WebSocket server started on port 8080")
    else:
        print("Failed to start server")

func _process(delta:float) -> void:
    if server and server.is_listening():
        # Process queued signals from background thread
        server.process()

func _on_client_connected(client_id: int):
    print("Client connected: ", client_id)
    server.send_text(client_id, "Welcome to the server!")

func _on_client_disconnected(client_id: int, code: int):
    print("Client disconnected: ", client_id, " with code: ", code)

func _on_message_received(client_id: int, message: String):
    print("Text from client ", client_id, ": ", message)
    # Echo message back
    server.send_text(client_id, "Echo: " + message)

func _on_data_received(client_id: int, data: PackedByteArray):
    print("Binary data from client ", client_id, ": ", data.size(), " bytes")
    # Echo binary data back
    server.send_binary(client_id, data)
```


## API Reference

### Methods

#### Server Control
- `bool start(int port = 8080, String host = "0.0.0.0")` - Start the WebSocket server
- `void stop()` - Stop the server and disconnect all clients
- `bool is_listening()` - Check if the server is running
- `void process()` - Process queued signals (call in `_process() or _physics_process()`)

#### Client Management
- `int get_client_count()` - Returns number of connected clients
- `TypedArray[int] get_client_ids()` - Returns an array of all client IDs

#### Communication
- `Error send_text(int client_id, String message)` - Send text message to specific client
- `Error send_binary(int client_id, PackedByteArray data)` - Send binary data to specific client
- `Error broadcast_text(String message)` - Send text message to all clients
- `Error broadcast_binary(PackedByteArray data)` - Send binary data to all clients

### Signals

- `client_connected(client_id: int)` - Emitted when a client connects
- `client_disconnected(client_id: int, code: int)` - Emitted when a client disconnects
- `message_received(client_id: int, message: String)` - Emitted when a text message is received
- `data_received(client_id: int, data: PackedByteArray)` - Emitted when binary data is received
- `server_error(error: String)` - Emitted on server errors


## Contributors:

### Opti
### Claude (Anthropic)

---

*This extension was created to fill the gap left by Godot 4's removal of the WebSocketServer class, providing a robust solution for networked applications.*