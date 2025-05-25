#ifndef WEBSOCKET_SERVER_H
#define WEBSOCKET_SERVER_H

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/variant/typed_array.hpp>
#include <godot_cpp/variant/variant.hpp>

#include <thread>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <memory>
#include <vector>
#include <queue>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif

namespace godot {

class WebSocketServer : public RefCounted {
    GDCLASS(WebSocketServer, RefCounted);

private:
    // Server properties
    int port;
    String host;
    std::atomic<bool> is_running;
    std::atomic<bool> should_exit;
    
    // Socket handling
    struct ClientConnection {
        int socket_fd;
        uint64_t id;
        bool is_websocket;
        std::vector<uint8_t> buffer;
        std::string websocket_key;
        bool handshake_completed;
    };
    
    int server_socket;
    std::unordered_map<uint64_t, ClientConnection> clients;
    uint64_t next_client_id;
    
    // Thread safety - use mutable to allow locking in const methods
    mutable std::mutex clients_mutex;
    std::thread server_thread;
    std::vector<int> pending_disconnects;
    
    // Signal queue for thread safety
    struct DeferredSignal {
        String name;
        std::vector<Variant> args;
    };
    std::queue<DeferredSignal> signal_queue;
    mutable std::mutex signal_mutex;
    
    // WebSocket protocol helper methods
    bool process_websocket_handshake(int client_socket, const std::string& request);
    bool set_socket_non_blocking(int socket_fd);
    void send_pong(int client_socket);
    
    // Thread-safe signal emission
    void queue_signal(const String& p_name, const std::vector<Variant>& p_args);
    
    // Server thread
    void server_thread_func();

protected:
    static void _bind_methods();

public:
    WebSocketServer();
    ~WebSocketServer();
    
    // Server control
    bool start(int p_port = 8080, const String &p_host = "0.0.0.0");
    void stop();
    bool is_listening() const;
    
	// Signal processing - call this from _process in GDScript
	void process();
	
    // Client management
    int get_client_count() const;
    TypedArray<int> get_client_ids() const;
    
    // Communication
    Error send_text(int p_client_id, const String &p_message);
    Error send_binary(int p_client_id, const PackedByteArray &p_data);
    Error broadcast_text(const String &p_message);
    Error broadcast_binary(const PackedByteArray &p_data);
};

}

#endif // WEBSOCKET_SERVER_H
