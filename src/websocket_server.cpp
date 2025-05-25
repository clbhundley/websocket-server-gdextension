#include "websocket_server.h"

#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/variant/utility_functions.hpp>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <vector>
#include <random>
#include <iomanip>

#ifdef _WIN32
// Windows-specific socket cleanup
#define close_socket closesocket
#else
// Unix-compatible close socket function
#define close_socket close
#endif

namespace godot {

// Base64 encoding/decoding helpers
static const std::string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";


static std::string base64_encode(const unsigned char *bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}


// SHA-1 implementation
static std::string calculate_sha1(const std::string& input) {
    // Using a simplified implementation - sufficient for WebSocket handshakes
    static const std::string websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string combined = input + websocket_guid;
    
    // Fixed values from the SHA-1 algorithm
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    
    // Message preparation (simplified for WebSocket handshake)
    std::string message = combined;
    
    // Process the message in 512-bit chunks
    size_t message_len = message.length();
    size_t total_len = message_len * 8; // Length in bits
    
    // For WebSocket, we're only handling small messages
    // Padding to multiple of 512 bits
    message += static_cast<char>(0x80); // Append bit '1'
    
    while ((message.length() * 8) % 512 != 448) {
        message += static_cast<char>(0x00); // Append bits '0'
    }
    
    // Append original length
    for (int i = 7; i >= 0; i--) {
        message += static_cast<char>((total_len >> (i * 8)) & 0xFF);
    }
    
    // Process all complete chunks
    for (size_t i = 0; i < message.length(); i += 64) {
        uint32_t w[80];
        
        // Break chunk into 16 32-bit big-endian words
        for (int j = 0; j < 16; j++) {
            w[j] = 0;
            for (int k = 0; k < 4; k++) {
                if (i + j * 4 + k < message.length()) {
                    w[j] = (w[j] << 8) | (message[i + j * 4 + k] & 0xFF);
                }
            }
        }
        
        // Extend the 16 words to 80
        for (int j = 16; j < 80; j++) {
            w[j] = (w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]);
            w[j] = (w[j] << 1) | (w[j] >> 31);
        }
        
        // Initialize hash values for this chunk
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        
        // Main loop
        for (int j = 0; j < 80; j++) {
            uint32_t f, k;
            
            if (j < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (j < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (j < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[j];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = temp;
        }
        
        // Add this chunk's hash to result
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    
    // Produce the final hash value
    unsigned char digest[20];
    
    digest[0] = (h0 >> 24) & 0xFF;
    digest[1] = (h0 >> 16) & 0xFF;
    digest[2] = (h0 >> 8) & 0xFF;
    digest[3] = h0 & 0xFF;
    
    digest[4] = (h1 >> 24) & 0xFF;
    digest[5] = (h1 >> 16) & 0xFF;
    digest[6] = (h1 >> 8) & 0xFF;
    digest[7] = h1 & 0xFF;
    
    digest[8] = (h2 >> 24) & 0xFF;
    digest[9] = (h2 >> 16) & 0xFF;
    digest[10] = (h2 >> 8) & 0xFF;
    digest[11] = h2 & 0xFF;
    
    digest[12] = (h3 >> 24) & 0xFF;
    digest[13] = (h3 >> 16) & 0xFF;
    digest[14] = (h3 >> 8) & 0xFF;
    digest[15] = h3 & 0xFF;
    
    digest[16] = (h4 >> 24) & 0xFF;
    digest[17] = (h4 >> 16) & 0xFF;
    digest[18] = (h4 >> 8) & 0xFF;
    digest[19] = h4 & 0xFF;
    
    return base64_encode(digest, 20);
}


// WebSocket frame creation
static std::string encode_websocket_frame(const std::vector<uint8_t>& data, bool text_mode) {
    std::string frame;
    
    // First byte: FIN bit (1) + RSV bits (000) + opcode (0001 for text, 0010 for binary)
    uint8_t first_byte = 0x80 | (text_mode ? 0x01 : 0x02);
    frame.push_back(first_byte);
    
    // Second byte: MASK bit (0) + payload length
    size_t length = data.size();
    
    if (length < 126) {
        // Length fits in 7 bits
        frame.push_back(static_cast<uint8_t>(length));
    } else if (length <= 0xFFFF) {
        // Length fits in 16 bits
        frame.push_back(126);
        frame.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(length & 0xFF));
    } else {
        // Length requires 64 bits (only using the lower 32 bits here)
        frame.push_back(127);
        
        // 8 bytes for length (we'll only use the lower 4)
        for (int i = 7; i >= 0; i--) {
            if (i >= 4) {
                frame.push_back(0); // Upper 4 bytes are 0
            } else {
                frame.push_back(static_cast<uint8_t>((length >> (i * 8)) & 0xFF));
            }
        }
    }
    
    // Add payload
    frame.append(reinterpret_cast<const char*>(data.data()), data.size());
    
    return frame;
}

// Encode a close frame
static std::string encode_websocket_close_frame(uint16_t code = 1000, const std::string& reason = "") {
    std::vector<uint8_t> payload;
    
    // Add status code in network byte order (big-endian)
    payload.push_back((code >> 8) & 0xFF);
    payload.push_back(code & 0xFF);
    
    // Add reason if provided
    if (!reason.empty()) {
        payload.insert(payload.end(), reason.begin(), reason.end());
    }
    
    // Create the frame
    std::string frame;
    
    // First byte: FIN bit (1) + RSV bits (000) + opcode (1000 for close)
    frame.push_back(0x88);
    
    // Second byte: MASK bit (0) + payload length
    frame.push_back(static_cast<uint8_t>(payload.size()));
    
    // Add payload
    frame.append(reinterpret_cast<const char*>(payload.data()), payload.size());
    
    return frame;
}


// Encode a ping frame
static std::string encode_websocket_ping_frame() {
    // First byte: FIN bit (1) + RSV bits (000) + opcode (1001 for ping)
    // Second byte: MASK bit (0) + payload length (0)
    return std::string("\x89\x00", 2);
}


// Encode a pong frame
static std::string encode_websocket_pong_frame() {
    // First byte: FIN bit (1) + RSV bits (000) + opcode (1010 for pong)
    // Second byte: MASK bit (0) + payload length (0)
    return std::string("\x8A\x00", 2);
}


static bool decode_websocket_frame(const std::vector<uint8_t>& in_buffer, 
                                  std::vector<uint8_t>& out_buffer, 
                                  uint8_t& opcode,
                                  bool& is_text,
                                  size_t& bytes_consumed) {
    
    try {
        // Check if we have enough data to read the header
        if (in_buffer.size() < 2) {
            bytes_consumed = 0;
            return false;
        }
        
        bytes_consumed = 0;
        
        // Read first byte
        uint8_t first_byte = in_buffer[0];
        bool fin = (first_byte & 0x80) != 0;
        opcode = first_byte & 0x0F;
        
        // Check if this is a control frame
        bool is_control = (opcode & 0x08) != 0;
        
        // Set text flag based on opcode
        is_text = (opcode == 0x01);
        
        // Read second byte
        uint8_t second_byte = in_buffer[1];
        bool masked = (second_byte & 0x80) != 0;
        uint64_t payload_length = second_byte & 0x7F;
        
        size_t header_size = 2;
        
        // Extended payload length
        if (payload_length == 126) {
            // 16-bit length
            if (in_buffer.size() < 4) {
                bytes_consumed = 0;
                return false; // Not enough data
            }
            
            payload_length = ((uint16_t)in_buffer[2] << 8) | in_buffer[3];
            header_size = 4;
        } else if (payload_length == 127) {
            // 64-bit length
            if (in_buffer.size() < 10) {
                bytes_consumed = 0;
                return false; // Not enough data
            }
            
            // We'll only use the lower 32 bits to avoid potential issues
            payload_length = 0;
            for (int i = 0; i < 4; i++) {
                payload_length = (payload_length << 8) | in_buffer[6 + i];
            }
            header_size = 10;
        }
        
        // Sanity check on payload length
        if (payload_length > 100 * 1024 * 1024) {  // 100 MB limit
            bytes_consumed = header_size;
            return false;
        }
        
        // Read masking key if masked
        uint8_t masking_key[4] = {0};
        if (masked) {
            if (in_buffer.size() < header_size + 4) {
                bytes_consumed = 0;
                return false; // Not enough data
            }
            
            for (int i = 0; i < 4; i++) {
                masking_key[i] = in_buffer[header_size + i];
            }
            
            header_size += 4;
        }
        
        // Check if we have the full payload
        if (in_buffer.size() < header_size + payload_length) {
            bytes_consumed = 0;
            return false; // Not enough data
        }
        
        // Extract payload
        out_buffer.resize(payload_length);
        for (uint64_t i = 0; i < payload_length; i++) {
            if (masked) {
                out_buffer[i] = in_buffer[header_size + i] ^ masking_key[i % 4];
            } else {
                out_buffer[i] = in_buffer[header_size + i];
            }
        }
        
        bytes_consumed = header_size + payload_length;

        return true;
    }
    catch (const std::exception& e) {
        UtilityFunctions::printerr("Exception in decode_websocket_frame: ", e.what());
        bytes_consumed = 0;
        return false;
    }
    catch (...) {
        UtilityFunctions::printerr("Unknown exception in decode_websocket_frame");
        bytes_consumed = 0;
        return false;
    }
}


WebSocketServer::WebSocketServer() : 
    port(8080), 
    host("0.0.0.0"), 
    is_running(false),
    should_exit(false),
    server_socket(-1),
    next_client_id(1) {
    
    // Initialize sockets on Windows
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        UtilityFunctions::printerr("WSAStartup failed");
    }
#endif
}


WebSocketServer::~WebSocketServer() {
    stop();
    
    // Cleanup sockets on Windows
#ifdef _WIN32
    WSACleanup();
#endif
}


bool WebSocketServer::set_socket_non_blocking(int socket_fd) {
#ifdef _WIN32
    u_long mode = 1;
    return (ioctlsocket(socket_fd, FIONBIO, &mode) == 0);
#else
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1) return false;
    return (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == 0);
#endif
}


bool WebSocketServer::process_websocket_handshake(int client_socket, const std::string& request) {
    try {
        UtilityFunctions::print("Processing WebSocket handshake...");
        
        // Extract WebSocket key
        std::string websocket_key;
        size_t key_pos = request.find("Sec-WebSocket-Key: ");
        
        if (key_pos != std::string::npos) {
            size_t key_end = request.find("\r\n", key_pos);
            if (key_end != std::string::npos) {
                websocket_key = request.substr(key_pos + 19, key_end - (key_pos + 19));
            }
        }
        
        if (websocket_key.empty()) {
            UtilityFunctions::printerr("WebSocket handshake failed: No Sec-WebSocket-Key found");
            return false;
        }
        
        // Generate WebSocket accept key
        std::string accept_key = calculate_sha1(websocket_key);
        
        // Create response
        std::string response = 
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " + accept_key + "\r\n"
            "\r\n";
        
        // Send response
        if (send(client_socket, response.c_str(), response.size(), 0) < 0) {
            UtilityFunctions::printerr("WebSocket handshake failed: Could not send response");
            return false;
        }
        
        UtilityFunctions::print("WebSocket handshake completed successfully");
        return true;
    }
    catch (const std::exception& e) {
        UtilityFunctions::printerr("Exception in WebSocket handshake: ", e.what());
        return false;
    }
    catch (...) {
        UtilityFunctions::printerr("Unknown exception in WebSocket handshake");
        return false;
    }
}


void WebSocketServer::queue_signal(const String& p_name, const std::vector<Variant>& p_args) {
    std::lock_guard<std::mutex> lock(signal_mutex);
    DeferredSignal signal = {p_name, p_args};
    signal_queue.push(signal);
}


void WebSocketServer::process() {
    std::lock_guard<std::mutex> lock(signal_mutex);
    while (!signal_queue.empty()) {
        DeferredSignal signal = signal_queue.front();
        signal_queue.pop();
        
        // Safely emit the signal from the main thread
        if (signal.name == "client_connected") {
            emit_signal("client_connected", signal.args[0]);
        }
        else if (signal.name == "client_disconnected") {
            emit_signal("client_disconnected", signal.args[0], signal.args[1]);
        }
        else if (signal.name == "message_received") {
            emit_signal("message_received", signal.args[0], signal.args[1]);
        }
        else if (signal.name == "data_received") {
            emit_signal("data_received", signal.args[0], signal.args[1]);
        }
        else if (signal.name == "server_error") {
            emit_signal("server_error", signal.args[0]);
        }
    }
}


void WebSocketServer::send_pong(int client_socket) {
    std::string pong_frame = encode_websocket_pong_frame();
    send(client_socket, pong_frame.c_str(), pong_frame.size(), 0);
}


void WebSocketServer::server_thread_func() {
    UtilityFunctions::print("WebSocket server thread started");
    
    // Simple loop - just accept connections and echo back any messages
    while (!should_exit.load(std::memory_order_relaxed)) {
        // Wait for a bit to avoid high CPU usage
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        // Accept new connections
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        
        if (client_socket != -1) {
            // Got a new connection
            uint64_t client_id = next_client_id++;
            
            // Set socket options for better reliability
            int opt = 1;
            setsockopt(client_socket, SOL_SOCKET, SO_KEEPALIVE, (const char*)&opt, sizeof(opt));
            
            // Set socket to non-blocking mode
            set_socket_non_blocking(client_socket);
            
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                clients[client_id] = {client_socket, client_id, false, {}, "", false};
            }
            
            UtilityFunctions::print("New client connected: ", client_id);
        }
        
        // Process existing clients
        std::vector<uint64_t> client_ids;
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            for (const auto& client_pair : clients) {
                client_ids.push_back(client_pair.first);
            }
        }
        
        for (uint64_t id : client_ids) {
            // For each client, check if there's any data to read
            ClientConnection client;
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                auto it = clients.find(id);
                if (it == clients.end()) {
                    continue;
                }
                client = it->second;
            }
            
            // Check if there's data to read
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(client.socket_fd, &read_fds);
            
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 0;
            
            if (select(client.socket_fd + 1, &read_fds, NULL, NULL, &tv) > 0) {
                // There's data to read
                char buffer[4096];
                int bytes_read = recv(client.socket_fd, buffer, sizeof(buffer), 0);
                
                if (bytes_read <= 0) {
                    // Connection closed or error
                    {
                        std::lock_guard<std::mutex> lock(clients_mutex);
                        clients.erase(id);
                    }
                    
                    close_socket(client.socket_fd);
                    
                    std::vector<Variant> args = {Variant((int)id), Variant(1000)};
                    queue_signal("client_disconnected", args);
                }
                else {
                    // Process received data
                    if (!client.handshake_completed) {
                        // This is the initial handshake
                        std::string request(buffer, bytes_read);
                        
                        // Check if it's a WebSocket handshake
                        if (request.find("GET ") == 0 && request.find("Upgrade: websocket") != std::string::npos) {
                            bool handshake_success = process_websocket_handshake(client.socket_fd, request);
                            
                            if (handshake_success) {
                                // Update client status
                                std::lock_guard<std::mutex> lock(clients_mutex);
                                auto it = clients.find(id);
                                if (it != clients.end()) {
                                    it->second.handshake_completed = true;
                                    it->second.is_websocket = true;
                                }
                                
                                std::vector<Variant> args = {Variant((int)id)};
                                queue_signal("client_connected", args);
                            }
                            else {
                                // Failed handshake
                                std::lock_guard<std::mutex> lock(clients_mutex);
                                clients.erase(id);
                                close_socket(client.socket_fd);
                            }
                        }
                        else {
                            // Not a WebSocket connection
                            UtilityFunctions::print("Received non-WebSocket request, closing connection");
                            std::lock_guard<std::mutex> lock(clients_mutex);
                            clients.erase(id);
                            close_socket(client.socket_fd);
                        }
                    }
                    else {
                        // This is WebSocket data - add to client's receive buffer
                        {
                            std::lock_guard<std::mutex> lock(clients_mutex);
                            auto it = clients.find(id);
                            if (it != clients.end()) {
                                // Append new data to the client's buffer
                                it->second.buffer.insert(
                                    it->second.buffer.end(),
                                    buffer, 
                                    buffer + bytes_read
                                );
                            }
                        }
                        
                        // Process all complete frames from the buffer
                        bool keep_processing = true;
                        while (keep_processing) {
                            std::vector<uint8_t> current_buffer;
                            {
                                std::lock_guard<std::mutex> lock(clients_mutex);
                                auto it = clients.find(id);
                                if (it == clients.end()) {
                                    break;
                                }
                                current_buffer = it->second.buffer;
                            }
                            
                            if (current_buffer.empty()) {
                                break;
                            }
                            
                            // Try to decode a WebSocket frame from the buffer
                            std::vector<uint8_t> payload;
                            uint8_t opcode = 0;
                            bool is_text = false;
                            size_t bytes_consumed = 0;
                            
                            if (decode_websocket_frame(current_buffer, payload, opcode, is_text, bytes_consumed)) {
                                // Successfully decoded a frame
                                
                                // Remove the consumed bytes from the client's buffer
                                {
                                    std::lock_guard<std::mutex> lock(clients_mutex);
                                    auto it = clients.find(id);
                                    if (it != clients.end()) {
                                        it->second.buffer.erase(
                                            it->second.buffer.begin(),
                                            it->second.buffer.begin() + bytes_consumed
                                        );
                                    }
                                }
                                
                                // Handle different opcodes
                                if (opcode == 0x01 || opcode == 0x02) {
                                    // Text or binary message
                                    if (opcode == 0x01) {
                                        // Text message
                                        std::string text_message(payload.begin(), payload.end());
                                        
                                        std::vector<Variant> args = {
                                            Variant((int)id),
                                            Variant(String(text_message.c_str()))
                                        };
                                        queue_signal("message_received", args);
                                    }
                                    else {
                                        // Binary message
                                        PackedByteArray binary_data;
                                        binary_data.resize(payload.size());
                                        memcpy(binary_data.ptrw(), payload.data(), payload.size());
                                        
                                        std::vector<Variant> args = {
                                            Variant((int)id),
                                            Variant(binary_data)
                                        };
                                        queue_signal("data_received", args);
                                    }
                                }
                                else if (opcode == 0x08) {
                                    // Close frame
                                    UtilityFunctions::print("Received close frame from client: ", id);
                                    
                                    // Send close frame in response
                                    std::string close_frame = encode_websocket_close_frame();
                                    send(client.socket_fd, close_frame.c_str(), close_frame.size(), 0);
                                    
                                    // Close the connection
                                    std::lock_guard<std::mutex> lock(clients_mutex);
                                    clients.erase(id);
                                    close_socket(client.socket_fd);
                                    
                                    std::vector<Variant> args = {Variant((int)id), Variant(1000)};
                                    queue_signal("client_disconnected", args);
                                    
                                    keep_processing = false; // Exit the processing loop
                                }
                                else if (opcode == 0x09) {
                                    // Ping frame - respond with pong
                                    send_pong(client.socket_fd);
                                }
                                else if (opcode == 0x0A) {
                                    // Pong frame - ignore
                                    UtilityFunctions::print("Received pong frame from client: ", id);
                                }
                                
                                // Continue processing if there might be more frames in the buffer
                                // (only if we haven't closed the connection)
                                if (opcode == 0x08) {
                                    keep_processing = false;
                                }
                            }
                            else {
                                // Could not decode a complete frame - wait for more data
                                if (bytes_consumed > 0) {
                                    // Partial frame or corrupted data - remove consumed bytes
                                    std::lock_guard<std::mutex> lock(clients_mutex);
                                    auto it = clients.find(id);
                                    if (it != clients.end()) {
                                        it->second.buffer.erase(
                                            it->second.buffer.begin(),
                                            it->second.buffer.begin() + bytes_consumed
                                        );
                                    }
                                }
                                keep_processing = false;
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Clean up all clients
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (const auto& client_pair : clients) {
            close_socket(client_pair.second.socket_fd);
        }
        clients.clear();
    }
    
    // Close the server socket
    if (server_socket != -1) {
        close_socket(server_socket);
        server_socket = -1;
    }
    
    is_running.store(false, std::memory_order_relaxed);
    UtilityFunctions::print("WebSocket server thread stopped");
}


bool WebSocketServer::start(int p_port, const String &p_host) {
    if (is_running.load(std::memory_order_relaxed)) {
        UtilityFunctions::printerr("WebSocket server already running");
        return false;
    }
    
    port = p_port;
    host = p_host;
    
    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    if (server_socket == -1) {
        UtilityFunctions::printerr("Failed to create socket");
        return false;
    }
    
    // Set socket to reuse address
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
        UtilityFunctions::printerr("Failed to set socket options");
        close_socket(server_socket);
        server_socket = -1;
        return false;
    }
    
    // Set TCP_NODELAY to improve responsiveness
    if (setsockopt(server_socket, IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt)) < 0) {
        UtilityFunctions::printerr("Failed to set TCP_NODELAY option");
        // Non-fatal, continue anyway
    }
    
    // Bind socket to address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Convert host string to address
    if (host == "0.0.0.0") {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        std::string host_str = host.utf8().get_data();
        
#ifdef _WIN32
        server_addr.sin_addr.s_addr = inet_addr(host_str.c_str());
        if (server_addr.sin_addr.s_addr == INADDR_NONE) {
#else
        if (inet_pton(AF_INET, host_str.c_str(), &server_addr.sin_addr) <= 0) {
#endif
            UtilityFunctions::printerr("Invalid address: ", host);
            close_socket(server_socket);
            server_socket = -1;
            return false;
        }
    }
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        UtilityFunctions::printerr("Failed to bind socket");
        close_socket(server_socket);
        server_socket = -1;
        return false;
    }
    
    // Listen for connections
    if (listen(server_socket, 5) < 0) {
        UtilityFunctions::printerr("Failed to listen on socket");
        close_socket(server_socket);
        server_socket = -1;
        return false;
    }
    
    // Set server socket to non-blocking mode
    if (!set_socket_non_blocking(server_socket)) {
        UtilityFunctions::printerr("Failed to set socket to non-blocking mode");
        close_socket(server_socket);
        server_socket = -1;
        return false;
    }
    
    // Start server thread
    should_exit.store(false, std::memory_order_relaxed);
    is_running.store(true, std::memory_order_relaxed);
    
    server_thread = std::thread(&WebSocketServer::server_thread_func, this);
    
    UtilityFunctions::print("WebSocket server started on ", host, ":", port);
    
    return true;
}


void WebSocketServer::stop() {
    if (!is_running.load(std::memory_order_relaxed)) {
        return;
    }
    
    // Signal the thread to exit
    should_exit.store(true, std::memory_order_relaxed);
    
    // Wait for thread to finish
    if (server_thread.joinable()) {
        server_thread.join();
    }
    
    UtilityFunctions::print("WebSocket server stopped");
}


bool WebSocketServer::is_listening() const {
    return is_running.load(std::memory_order_relaxed);
}


int WebSocketServer::get_client_count() const {
    std::lock_guard<std::mutex> lock(clients_mutex);
    return static_cast<int>(clients.size());
}


TypedArray<int> WebSocketServer::get_client_ids() const {
    TypedArray<int> result;
    
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto& client_pair : clients) {
        result.push_back(static_cast<int>(client_pair.first));
    }
    
    return result;
}


Error WebSocketServer::send_text(int p_client_id, const String &p_message) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = clients.find(p_client_id);
    if (it == clients.end()) {
        return ERR_INVALID_PARAMETER;
    }
    
    if (!it->second.handshake_completed) {
        return ERR_UNAVAILABLE;
    }
    
    std::string message = p_message.utf8().get_data();
    std::vector<uint8_t> data(message.begin(), message.end());
    
    std::string frame = encode_websocket_frame(data, true);
    
    if (send(it->second.socket_fd, frame.c_str(), frame.size(), 0) == -1) {
        return ERR_UNAVAILABLE;
    }
    
    return OK;
}


Error WebSocketServer::send_binary(int p_client_id, const PackedByteArray &p_data) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = clients.find(p_client_id);
    if (it == clients.end()) {
        return ERR_INVALID_PARAMETER;
    }
    
    if (!it->second.handshake_completed) {
        return ERR_UNAVAILABLE;
    }
    
    std::vector<uint8_t> data(p_data.ptr(), p_data.ptr() + p_data.size());
    std::string frame = encode_websocket_frame(data, false);
    
    if (send(it->second.socket_fd, frame.c_str(), frame.size(), 0) == -1) {
        return ERR_UNAVAILABLE;
    }
    
    return OK;
}


Error WebSocketServer::broadcast_text(const String &p_message) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    std::string message = p_message.utf8().get_data();
    std::vector<uint8_t> data(message.begin(), message.end());
    std::string frame = encode_websocket_frame(data, true);
    
    for (const auto& client_pair : clients) {
        if (client_pair.second.handshake_completed) {
            send(client_pair.second.socket_fd, frame.c_str(), frame.size(), 0);
        }
    }
    
    return OK;
}


Error WebSocketServer::broadcast_binary(const PackedByteArray &p_data) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    std::vector<uint8_t> data(p_data.ptr(), p_data.ptr() + p_data.size());
    std::string frame = encode_websocket_frame(data, false);
    
    for (const auto& client_pair : clients) {
        if (client_pair.second.handshake_completed) {
            send(client_pair.second.socket_fd, frame.c_str(), frame.size(), 0);
        }
    }
    
    return OK;
}


void WebSocketServer::_bind_methods() {
    // Register methods
    ClassDB::bind_method(D_METHOD("start", "port", "host"), &WebSocketServer::start, DEFVAL(8080), DEFVAL("0.0.0.0"));
    ClassDB::bind_method(D_METHOD("stop"), &WebSocketServer::stop);
    ClassDB::bind_method(D_METHOD("is_listening"), &WebSocketServer::is_listening);
    ClassDB::bind_method(D_METHOD("get_client_count"), &WebSocketServer::get_client_count);
    ClassDB::bind_method(D_METHOD("get_client_ids"), &WebSocketServer::get_client_ids);
    ClassDB::bind_method(D_METHOD("send_text", "client_id", "message"), &WebSocketServer::send_text);
    ClassDB::bind_method(D_METHOD("send_binary", "client_id", "data"), &WebSocketServer::send_binary);
    ClassDB::bind_method(D_METHOD("broadcast_text", "message"), &WebSocketServer::broadcast_text);
    ClassDB::bind_method(D_METHOD("broadcast_binary", "data"), &WebSocketServer::broadcast_binary);
    ClassDB::bind_method(D_METHOD("process"), &WebSocketServer::process);
    
    // Register signals
    ADD_SIGNAL(MethodInfo("client_connected", PropertyInfo(Variant::INT, "client_id")));
    ADD_SIGNAL(MethodInfo("client_disconnected", PropertyInfo(Variant::INT, "client_id"), PropertyInfo(Variant::INT, "code")));
    ADD_SIGNAL(MethodInfo("message_received", PropertyInfo(Variant::INT, "client_id"), PropertyInfo(Variant::STRING, "message")));
    ADD_SIGNAL(MethodInfo("data_received", PropertyInfo(Variant::INT, "client_id"), PropertyInfo(Variant::PACKED_BYTE_ARRAY, "data")));
    ADD_SIGNAL(MethodInfo("server_error", PropertyInfo(Variant::STRING, "error")));
}

}
