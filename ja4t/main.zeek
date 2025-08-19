# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Licensed under FoxIO License 1.1
# For full license text and more details, see the repo root [https://github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)
# JA4+ by John Althouse
# Zeek script by Jo Johnson
module FINGERPRINT::JA4T;
@load ../config
@load ../utils/common

export {
    # TODO: It would be nice to make this on par wtih the tcp_options event
    type TCP_Options: record {
        option_kinds: vector of count &default=vector();
        max_segment_size: count &default=0;
        window_scale: count &default=0;
    };
    
    # The fingerprint context 
    type Info: record {
        syn_window_size: count &default=0;
        syn_opts: TCP_Options &default=TCP_Options();    
        synack_window_size: count &default=0;
        synack_opts: TCP_Options &default=TCP_Options();
        synack_delays: vector of count &default=vector();
        synack_done: bool &default=F;
        ja4t_done: bool &default=F;
        last_ts: double &default=0;
        rst_ts: double &default=0;
    };
    
    # Отдельный лог для быстрого JA4T
    type FastJA4T: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        ja4t: string &log;
    };
    
    redef enum Log::ID += { FAST_LOG };
    global log_fast_ja4t: event(rec: FastJA4T);
    global fast_log_policy: Log::PolicyHook;
}

redef record FINGERPRINT::Info += {
    ja4t: FINGERPRINT::JA4T::Info &default= Info();
};

redef record Conn::Info += {
    ja4t: string &log &default = "";
};

@if(FINGERPRINT::JA4TS_enabled)
redef record Conn::Info += {
    ja4ts: string &log &default = "";
};
@endif

# Create the fast log stream
event zeek_init() &priority=5 {
    Log::create_stream(FINGERPRINT::JA4T::FAST_LOG,
        [$columns=FastJA4T, $ev=log_fast_ja4t, $path="ja4t_fast", $policy=fast_log_policy]);
}

function get_current_packet_timestamp(): double {
    local cp = get_current_packet();
    return cp$ts_sec * 1000000.0 + cp$ts_usec;
}

function get_tcp_options(): TCP_Options {
    local opts: TCP_Options;
    local rph = get_current_packet_header();
    if (!rph?$tcp || rph$tcp$hl <= 20 ) {
        return opts;
    }
    local pkt = get_current_packet();
    if (rph$l2$encap != LINK_ETHERNET) {
        return opts;
    }
    local offset = 12;
    # handle vlan including triple tagging
    while (offset + 2 < pkt$caplen) {
        local link_header_type = bytestring_to_count(pkt$data[offset:offset+2]);
        if (link_header_type == 0x8100 || link_header_type == 0x8A88) {
            offset += 4;
            next;
        } else if (link_header_type == 0x0800) {  # IPv4            
            offset += 2 + rph$ip$hl;
            break;
        } else if (link_header_type == 0x86DD) {  # IPv6
            offset += 2 + 40;   # We know we're TCP.  There might be options.
            break;
        } else {
            return opts;  # Not sure where TCP header will start
        }
    }
    local header_end = offset + rph$tcp$hl;
    if (header_end > pkt$caplen) {
        return opts;
    }
    offset += 20;  # skip base tcp header
    while(offset < header_end) {
        local opt_kind = bytestring_to_count(pkt$data[offset]);
        if (opt_kind == 0) {
            break;
        }
        opts$option_kinds += opt_kind;
        if (opt_kind == 1  || offset + 1 >= header_end) {
            offset += 1;
            next;
        }
        local opt_len = bytestring_to_count(pkt$data[offset + 1]);
        if (opt_len < 2) {
            return opts;  # Conversion failure or corrupt packet
        }
        if (opt_kind == 2 && offset + 3 < header_end) {
            opts$max_segment_size = bytestring_to_count(pkt$data[offset+2:offset+4]);
        }
        if (opt_kind == 3 && offset + 2 < header_end) {
            opts$window_scale = bytestring_to_count(pkt$data[offset+2]);
        }
        offset += opt_len;
    }
    return opts;
}

# Функция для немедленного формирования ja4t и записи в быстрый лог
function do_ja4t_fast(c: connection) {
    if (!c?$fp || c$fp$ja4t$ja4t_done || c$fp$ja4t$syn_window_size == 0) { 
        return; 
    }
    
    # Формируем ja4t сразу на основе SYN пакета
    local ja4t_value = fmt("%d", c$fp$ja4t$syn_window_size);
    ja4t_value += FINGERPRINT::delimiter;
    ja4t_value += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$syn_opts$option_kinds, "%d", "-");
    ja4t_value += FINGERPRINT::delimiter;
    ja4t_value += fmt("%d", c$fp$ja4t$syn_opts$max_segment_size);
    ja4t_value += FINGERPRINT::delimiter;
    ja4t_value += fmt("%d", c$fp$ja4t$syn_opts$window_scale);
    
    # СРАЗУ записываем в отдельный быстрый лог
    local fast_record = FastJA4T($ts=network_time(), $uid=c$uid, $id=c$id, $ja4t=ja4t_value);
    Log::write(FINGERPRINT::JA4T::FAST_LOG, fast_record);
    
    # Также записываем в conn для совместимости
    c$conn$ja4t = ja4t_value;
    c$fp$ja4t$ja4t_done = T;
}

event new_connection(c: connection) {
    local rph = get_current_packet_header();
    if (!rph?$tcp || rph$tcp$flags != TH_SYN) {
        return;  
    }
    if(!c?$fp) { c$fp = FINGERPRINT::Info(); }
    
    c$fp$ja4t$syn_window_size = rph$tcp$win;
    c$fp$ja4t$syn_opts = get_tcp_options();
    c$fp$ja4t$last_ts = get_current_packet_timestamp();
    
    # Формируем ja4t сразу после SYN и записываем в быстрый лог
    do_ja4t_fast(c);
    
    ConnThreshold::set_packets_threshold(c,1,F);  # start monitoring synacks
    ConnThreshold::set_packets_threshold(c,2,T);  # Shut down ja4TS on next orig packet
}

event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) {
    
    # stop ts on any orig packet
    if(is_orig) {
        if(c?$fp) {
            c$fp$ja4t$synack_done = T;
        }
        return;
    }
    # No more ts work to do
    if(!c?$fp || c$fp$ja4t$synack_done) {
        return;
    }
    local rph = get_current_packet_header();
    if (!rph?$tcp) {
        return;  
    }
    local ts = get_current_packet_timestamp();
    if (ts - c$fp$ja4t$last_ts > 120000000) { # Timeout.  
        c$fp$ja4t$synack_done = T;
        return;
    } 
    if (rph$tcp$flags & TH_RST != 0) {
        c$fp$ja4t$rst_ts = ts;
        c$fp$ja4t$synack_done = T;
        return;   # We'll handle tacking this on when we calculate 
    } else if (rph$tcp$flags == (TH_SYN | TH_ACK)) {
    } else {
        return;
    }
    if (threshold == 1) {  # first synack
        c$fp$ja4t$synack_window_size = rph$tcp$win;
        c$fp$ja4t$synack_opts = get_tcp_options();
    } else {
        c$fp$ja4t$synack_delays += double_to_count(ts - c$fp$ja4t$last_ts)/1000000;
    }
    c$fp$ja4t$last_ts = ts;
    
    if (|c$fp$ja4t$synack_delays| == 10) {
        return;
    } 
    @if(FINGERPRINT::JA4TS_enabled) 
        ConnThreshold::set_packets_threshold(c,threshold + 1,F);
    @endif
}

event connection_state_remove(c: connection) {
    # ja4t уже выведен в быстрый лог, здесь только ja4ts в conn.log
    @if(FINGERPRINT::JA4TS_enabled) 
    if(c?$fp && c$fp$ja4t$synack_window_size > 0) {
        c$conn$ja4ts = fmt("%d", c$fp$ja4t$synack_window_size);
        c$conn$ja4ts += FINGERPRINT::delimiter;
        c$conn$ja4ts += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$synack_opts$option_kinds, "%d", "-");
        c$conn$ja4ts += FINGERPRINT::delimiter;
        c$conn$ja4ts += fmt("%d", c$fp$ja4t$synack_opts$max_segment_size);
        c$conn$ja4ts += FINGERPRINT::delimiter;
        c$conn$ja4ts += fmt("%d", c$fp$ja4t$synack_opts$window_scale);
        if(|c$fp$ja4t$synack_delays| > 0) {
            c$conn$ja4ts += FINGERPRINT::delimiter;
            c$conn$ja4ts += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$synack_delays, "%d", "-");
            if(c$fp$ja4t$rst_ts > 0) {
                c$conn$ja4ts += fmt("-R%d", double_to_count(c$fp$ja4t$rst_ts - c$fp$ja4t$last_ts)/1000000);
            }   
        }
    }
    @endif
}
