# Copyright (c) 2024, FoxIO, LLC. 
# Simplified JA4L - fast output, no backup logs

module FINGERPRINT::JA4L;

export {
    type Info: record {
        # Timestamps for TCP
        syn: double &default = 0;
        synack: double &default = 0; 
        ack: double &default = 0;
        client_hello: double &default=0;
        server_hello: double &default=0;
        first_client_data: double &default=0;
        # Timestamps for QUIC
        client_init: double &default = 0;
        server_init: double &default = 0;
        client_handshake: double &default = 0;
        server_handshake: double &default = 0;
        ttl_c: count &default = 0;
        ttl_s: count &default = 0;
    };
}

redef record FINGERPRINT::Info += {
    ja4l: FINGERPRINT::JA4L::Info &default=Info();
};

redef record Conn::Info += {
    ja4l: string &log &default = "";
    ja4ls: string &log &default = "";
};

function get_current_packet_timestamp(): double {
    local cp = get_current_packet();
    return cp$ts_sec * 1000000.0 + cp$ts_usec;
}

# Быстрое формирование JA4L
function do_ja4l_fast(c: connection) {
    if (c$fp$ja4l$ack > 0 && c$conn$ja4l == "") {
        c$conn$ja4l = cat(double_to_count((c$fp$ja4l$ack - c$fp$ja4l$synack) / 2.0));
        c$conn$ja4l += FINGERPRINT::delimiter;
        c$conn$ja4l += cat(c$fp$ja4l$ttl_c);
        
        # Добавляем SSL данные если есть
        if (c$fp$ja4l$first_client_data > 0) {
            c$conn$ja4l += FINGERPRINT::delimiter;
            c$conn$ja4l += cat(double_to_count((c$fp$ja4l$first_client_data - c$fp$ja4l$server_hello) / 2.0));
        }
        
        print fmt("JA4L: %s = %s", c$uid, c$conn$ja4l);
    }
}

# Быстрое формирование JA4LS  
function do_ja4ls_fast(c: connection) {
    if (c$fp$ja4l$synack > 0 && c$conn$ja4ls == "") {
        c$conn$ja4ls = cat(double_to_count((c$fp$ja4l$synack - c$fp$ja4l$syn) / 2.0));
        c$conn$ja4ls += FINGERPRINT::delimiter;
        c$conn$ja4ls += cat(c$fp$ja4l$ttl_s);
        
        # Добавляем SSL данные если есть
        if (c$fp$ja4l$server_hello > 0) {
            c$conn$ja4ls += FINGERPRINT::delimiter;
            c$conn$ja4ls += cat(double_to_count((c$fp$ja4l$server_hello - c$fp$ja4l$client_hello) / 2.0));
        }
        
        print fmt("JA4LS: %s = %s", c$uid, c$conn$ja4ls);
    }
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
        # Формируем JA4L сразу после ACK
        do_ja4l_fast(c);
        
    } else if (is_orig && c?$fp && c$fp$ja4l$server_hello != 0 && c$fp$ja4l$first_client_data == 0) {
        if (rp?$tcp && rp$tcp$dl == 0) {
            ConnThreshold::set_packets_threshold(c,threshold + 1,T);              
            return;
        }
        c$fp$ja4l$first_client_data = get_current_packet_timestamp(); 
        # Обновляем JA4L с SSL данными
        c$conn$ja4l = ""; # Сбрасываем для пересчета с SSL
        do_ja4l_fast(c);
        
    } else if (threshold == 1) {
        c$fp$ja4l$synack = get_current_packet_timestamp();
        if(!rp?$tcp) {
            return;
        }
        if (rp?$ip) {
            c$fp$ja4l$ttl_s = rp$ip$ttl;
        } else if (rp?$ip6) {
            c$fp$ja4l$ttl_s = rp$ip6$hlim;
        } else {
            return;
        }
        # Формируем JA4LS сразу после SYN-ACK
        do_ja4ls_fast(c);
        
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
        return;
    }
    if (c?$fp && c$fp$ja4l$server_hello == 0) {
        c$fp$ja4l$server_hello = get_current_packet_timestamp();
        # Обновляем JA4LS с SSL данными
        c$conn$ja4ls = ""; # Сбрасываем для пересчета с SSL
        do_ja4ls_fast(c);
        
        ConnThreshold::set_packets_threshold(c,c$orig$num_pkts + 1,T);
    }
}

# QUIC поддержка
event QUIC::initial_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) {
    if(!c?$fp) { c$fp = FINGERPRINT::Info(); }
    local rp = get_current_packet_header();
    if (is_orig) {
        if (rp?$ip) {
            c$fp$ja4l$ttl_c = rp$ip$ttl;
        } else if (rp?$ip6) {
            c$fp$ja4l$ttl_c = rp$ip6$hlim;    
        }
        c$fp$ja4l$client_init = get_current_packet_timestamp();
    } else {
        if (rp?$ip) {
            c$fp$ja4l$ttl_s = rp$ip$ttl;
        } else if (rp?$ip6) {
            c$fp$ja4l$ttl_s = rp$ip6$hlim;    
        }
        c$fp$ja4l$server_init = get_current_packet_timestamp();
        # QUIC JA4LS
        c$conn$ja4ls = cat(double_to_count((c$fp$ja4l$server_init - c$fp$ja4l$client_init) / 2.0));
        c$conn$ja4ls += FINGERPRINT::delimiter;
        c$conn$ja4ls += cat(c$fp$ja4l$ttl_s);
        c$conn$ja4ls += FINGERPRINT::delimiter;
        c$conn$ja4ls += "q";
        
        print fmt("JA4LS QUIC: %s = %s", c$uid, c$conn$ja4ls);
    }
}

event QUIC::handshake_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) {
    if(!c?$fp || c$fp$ja4l$client_handshake != 0)  { 
        return;
    }
    if (is_orig) {
        c$fp$ja4l$client_handshake = get_current_packet_timestamp();
        # QUIC JA4L
        c$conn$ja4l = cat(double_to_count((c$fp$ja4l$client_handshake - c$fp$ja4l$server_handshake) / 2.0));
        c$conn$ja4l += FINGERPRINT::delimiter;
        c$conn$ja4l += cat(c$fp$ja4l$ttl_c);
        c$conn$ja4l += FINGERPRINT::delimiter;
        c$conn$ja4l += "q";
        
        print fmt("JA4L QUIC: %s = %s", c$uid, c$conn$ja4l);
    } else {
        c$fp$ja4l$server_handshake = get_current_packet_timestamp();
    }
}

event connection_state_remove(c: connection) {
    # Финальная проверка - если что-то не записалось
    if (c?$fp) {
        do_ja4l_fast(c);
        do_ja4ls_fast(c);
    }
}
