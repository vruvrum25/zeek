# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Licensed under FoxIO License 1.1
# For full license text and more details, see the repo root [https://github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)
# JA4+ by John Althouse
# Zeek script by Jo Johnson
# NOTE: JA4L can not work when traffic is out of order
module FINGERPRINT::JA4L;

export {
    # The fingerprint context and logging format
    type Info: record {
        # The connection uid which this fingerprint represents
        ts: time &log &optional;
        uid: string &log &optional;
        id: conn_id &log &optional;
        # The lightspeed fingerprints
        ja4l_c: string &log &default="";
        ja4l_s: string &log &default="";
        # Flags for immediate output
        ja4l_c_ready: bool &default=F;
        ja4l_s_ready: bool &default=F;
        ja4l_done: bool &default=F;
        ja4ls_done: bool &default=F;  # Флаг для предотвращения дублирования JA4LS
        # Timestamps for TCP
        syn: double &default = 0;   # A
        synack: double &default = 0; # B
        ack: double &default = 0;  # C
        client_hello: double &default=0; # D  
        server_hello: double &default=0; # E
        first_client_data: double &default=0; # F
        # Timestamps for QUIC
        client_init: double &default = 0;
        server_init: double &default = 0;
        client_handshake: double &default = 0;
        server_handshake: double &default = 0;
        ttl_c: count &default = 0;
        ttl_s: count &default = 0;
        first_server_data_ts: double &default = 0;  # Время первых серверных данных
    };
    
    # Отдельный лог для быстрого JA4L
    type FastJA4L: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        ja4l: string &log;
    };
    
    # Отдельный лог для умного JA4LS (один раз)
    type SmartJA4LS: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        ja4ls: string &log;
        protocol_type: string &log;  # TCP или QUIC
        export_reason: string &log;   # Причина экспорта
    };
    
    # Logging boilerplate
    redef enum Log::ID += { LOG, FAST_LOG, SMART_LS_LOG };
    global log_fingerprint_ja4l: event(rec: Info);
    global log_fast_ja4l: event(rec: FastJA4L);
    global log_smart_ja4ls: event(rec: SmartJA4LS);
    global log_policy: Log::PolicyHook;
    global fast_log_policy: Log::PolicyHook;
    global smart_ls_log_policy: Log::PolicyHook;
}

redef record FINGERPRINT::Info += {
    ja4l: FINGERPRINT::JA4L::Info &default=Info();
};

redef record Conn::Info += {
    ja4l: string &log &default = "";
    ja4ls: string &log &default = "";
};

# Create the log streams
event zeek_init() &priority=5 {
    Log::create_stream(FINGERPRINT::JA4L::LOG,
        [$columns=FINGERPRINT::JA4L::Info, $ev=log_fingerprint_ja4l, $path="fingerprint_ja4l", $policy=log_policy]);
    
    Log::create_stream(FINGERPRINT::JA4L::FAST_LOG,
        [$columns=FastJA4L, $ev=log_fast_ja4l, $path="ja4l_fast", $policy=fast_log_policy]);
    
    Log::create_stream(FINGERPRINT::JA4L::SMART_LS_LOG,
        [$columns=SmartJA4LS, $ev=log_smart_ja4ls, $path="ja4ls_smart", $policy=smart_ls_log_policy]);
}

function get_current_packet_timestamp(): double {
    local cp = get_current_packet();
    return cp$ts_sec * 1000000.0 + cp$ts_usec;
}

# Функция для немедленного формирования ja4l и записи в быстрый лог
function do_ja4l_fast(c: connection) {
    if (!c?$fp || c$fp$ja4l$ja4l_done) { 
        return; 
    }
    
    # Формируем ja4l если готовы компоненты
    if (c$fp$ja4l$ja4l_c != "") {
        # СРАЗУ записываем в отдельный быстрый лог
        local fast_record = FastJA4L($ts=network_time(), $uid=c$uid, $id=c$id, $ja4l=c$fp$ja4l$ja4l_c);
        Log::write(FINGERPRINT::JA4L::FAST_LOG, fast_record);
        
        # Также записываем в conn для совместимости
        c$conn$ja4l = c$fp$ja4l$ja4l_c;
        c$fp$ja4l$ja4l_done = T;
        
        print fmt("JA4L recorded: %s", c$uid);
    }
}

# Умная функция для формирования ja4ls - записывается ТОЛЬКО ОДИН РАЗ
function do_ja4ls_smart(c: connection) {
    if (!c?$fp || c$fp$ja4l$ja4ls_done || c$fp$ja4l$ja4l_s == "") {
        return;
    }
    
    # Определяем, стоит ли записывать JA4LS сейчас
    local should_write = F;
    local reason = "";
    local protocol_type = "tcp";
    local now = get_current_packet_timestamp();
    
    # Условия для записи JA4LS:
    if (c$fp$ja4l$server_hello > 0) {
        # 1. SSL handshake завершен
        should_write = T;
        reason = "ssl_ready";
    } else if (c$fp$ja4l$ja4l_s != "" && strstr(c$fp$ja4l$ja4l_s, "q") > 0) {
        # 2. QUIC соединение готово
        should_write = T;
        reason = "quic_ready";
        protocol_type = "quic";
    } else if (c$fp$ja4l$synack > 0 && (now - c$fp$ja4l$synack) > 1000000) {
        # 3. Прошла 1 секунда с SYN-ACK
        should_write = T;
        reason = "timeout_1sec";
    } else if (c$fp$ja4l$first_server_data_ts > 0) {
        # 4. Получены первые данные от сервера
        should_write = T;
        reason = "server_data";
    }
    
    if (!should_write) {
        return;
    }
    
    # ЗАПИСЫВАЕМ JA4LS ТОЛЬКО ОДИН РАЗ в умный лог
    local smart_ls_record = SmartJA4LS($ts=network_time(), $uid=c$uid, $id=c$id,
                                       $ja4ls=c$fp$ja4l$ja4l_s, $protocol_type=protocol_type,
                                       $export_reason=reason);
    Log::write(FINGERPRINT::JA4L::SMART_LS_LOG, smart_ls_record);
    
    # Также записываем в conn для совместимости
    c$conn$ja4ls = c$fp$ja4l$ja4l_s;
    c$fp$ja4l$ja4ls_done = T;  # ВАЖНО: помечаем как обработанный
    
    print fmt("JA4LS recorded ONCE: %s, reason: %s, protocol: %s", 
              c$uid, reason, protocol_type);
}

event new_connection(c: connection) {
    if(!c?$fp) { c$fp = FINGERPRINT::Info(); }
    
    local rp = get_current_packet_header();
    if (rp?$tcp && rp$tcp$flags != TH_SYN) {
        return;  
    }
    c$fp$ja4l$syn = get_current_packet_timestamp();
    if (rp?$ip) {
        c$fp$ja4l$ttl_c = rp$ip$ttl;
    } else if (rp?$ip6) {
        c$fp$ja4l$ttl_c = rp$ip6$hlim;    
    } else {
        return;  
    }
    ConnThreshold::set_packets_threshold(c,1,F);
}

event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) {
    local rp = get_current_packet_header();
    if (is_orig && threshold == 2) {
        c$fp$ja4l$ack = get_current_packet_timestamp();
        c$fp$ja4l$ja4l_c = cat(double_to_count( (c$fp$ja4l$ack - c$fp$ja4l$synack) / 2.0));
        c$fp$ja4l$ja4l_c += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_c += cat(c$fp$ja4l$ttl_c);
        c$fp$ja4l$uid = c$uid;
        c$fp$ja4l$ts = c$start_time;
        c$fp$ja4l$id = c$id;
        c$fp$ja4l$ja4l_c_ready = T;
        
        # Формируем ja4l сразу после готовности и записываем в быстрый лог
        do_ja4l_fast(c);
        
    } else if (is_orig && c?$fp && c$fp$ja4l$server_hello != 0 && c$fp$ja4l$first_client_data == 0) {
        if (rp?$tcp && rp$tcp$dl == 0) {
            # wait for actual  data
            ConnThreshold::set_packets_threshold(c,threshold + 1,T);              
            return;
        }
        c$fp$ja4l$first_client_data = get_current_packet_timestamp(); 
        c$fp$ja4l$ja4l_c += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_c += cat(double_to_count( (c$fp$ja4l$first_client_data - c$fp$ja4l$server_hello) / 2.0));
        
        # Обновляем ja4l с SSL данными и записываем в быстрый лог
        do_ja4l_fast(c);
        
    } else if (threshold != 1) {
        return; 
    } else {
        c$fp$ja4l$synack = get_current_packet_timestamp();
        if(!rp?$tcp) {
            # UDP only works for QUIC that is handled separately
            return;
        }
        if (rp?$ip) {
            c$fp$ja4l$ttl_s = rp$ip$ttl;
        } else if (rp?$ip6) {
            c$fp$ja4l$ttl_s = rp$ip6$hlim;
        } else {
            return;   #breaks the chain
        }
        c$fp$ja4l$ja4l_s = cat(double_to_count((c$fp$ja4l$synack - c$fp$ja4l$syn) / 2.0 ));
        c$fp$ja4l$ja4l_s += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_s += cat(c$fp$ja4l$ttl_s);
        c$fp$ja4l$ja4l_s_ready = T;
        
        # Пробуем записать JA4LS сразу после формирования базовых данных
        do_ja4ls_smart(c);
        
        ConnThreshold::set_packets_threshold(c,c$orig$num_pkts + 1,T);  
    }
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time,
 client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) 
{
    if (c?$fp && c$fp$ja4l$client_hello == 0) {
        c$fp$ja4l$client_hello = get_current_packet_timestamp();
    }
}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, 
  server_random: string, session_id: string, cipher: count, comp_method: count) 
{
    local rp = get_current_packet_header();
    if(!rp?$tcp) {
            # UDP only works for QUIC that is handled separately
            return;
        }
    if (c?$fp && c$fp$ja4l$server_hello == 0) {
        c$fp$ja4l$server_hello = get_current_packet_timestamp();
        c$fp$ja4l$first_server_data_ts = c$fp$ja4l$server_hello;
        c$fp$ja4l$ja4l_s += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_s += cat(double_to_count((c$fp$ja4l$server_hello - c$fp$ja4l$client_hello) / 2.0 ));
        
        # Записываем JA4LS с SSL данными
        do_ja4ls_smart(c);
        
        # get F on next orig packet
        ConnThreshold::set_packets_threshold(c,c$orig$num_pkts + 1,T);
    }
}

event QUIC::initial_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) {
    if(!c?$fp) { c$fp = FINGERPRINT::Info(); }
    local rp = get_current_packet_header();
    if (is_orig) {
        if (rp?$ip) {
            c$fp$ja4l$ttl_c = rp$ip$ttl;
        } else if (rp?$ip6) {
            c$fp$ja4l$ttl_c = rp$ip6$hlim;    
        } else {
            return;  
        }
        c$fp$ja4l$client_init = get_current_packet_timestamp();
        
    } else {
        if (rp?$ip) {
            c$fp$ja4l$ttl_s = rp$ip$ttl;
        } else if (rp?$ip6) {
            c$fp$ja4l$ttl_s = rp$ip6$hlim;    
        } else {
            return;  
        }
        c$fp$ja4l$server_init = get_current_packet_timestamp();
        c$fp$ja4l$first_server_data_ts = c$fp$ja4l$server_init;
        c$fp$ja4l$ja4l_s = cat(double_to_count( (c$fp$ja4l$server_init - c$fp$ja4l$client_init) / 2.0));
        c$fp$ja4l$ja4l_s += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_s += cat(c$fp$ja4l$ttl_s);
        c$fp$ja4l$ja4l_s += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_s += "q";
        c$fp$ja4l$ja4l_s_ready = T;
        
        # Записываем JA4LS для QUIC сразу
        do_ja4ls_smart(c);
    }
}

event QUIC::handshake_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) {
    if(!c?$fp || c$fp$ja4l$client_handshake != 0)  { 
        # No init packet, or client handshake already seen and logged
        return;
    }
    if (is_orig) {
        c$fp$ja4l$client_handshake = get_current_packet_timestamp();
        c$fp$ja4l$ja4l_c = cat(double_to_count( (c$fp$ja4l$client_handshake - c$fp$ja4l$server_handshake) / 2.0));
        c$fp$ja4l$ja4l_c += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_c += cat(c$fp$ja4l$ttl_c);
        c$fp$ja4l$ja4l_c += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_c += "q";
        c$fp$ja4l$ja4l_c_ready = T;
        
        # Формируем ja4l для QUIC клиента и записываем в быстрый лог
        do_ja4l_fast(c);
    } else {
        c$fp$ja4l$server_handshake = get_current_packet_timestamp();
        c$fp$ja4l$first_server_data_ts = c$fp$ja4l$server_handshake;
        
        # Обновляем JA4LS с QUIC handshake данными
        do_ja4ls_smart(c);
    }
}

event connection_state_remove(c: connection) {
    # Оба отпечатка уже выведены в быстрые логи
    # Последняя попытка для JA4LS если не записан
    if (c?$fp && !c$fp$ja4l$ja4ls_done && c$fp$ja4l$ja4l_s != "") {
        do_ja4ls_smart(c);
    }
}
