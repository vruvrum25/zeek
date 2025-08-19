# Copyright (c) 2024, FoxIO, LLC.
# Simplified JA4T - fast output, no backup logs

module FINGERPRINT::JA4T;
@load ../config
@load ../utils/common

export {
    type TCP_Options: record {
        option_kinds: vector of count &default=vector();
        max_segment_size: count &default=0;
        window_scale: count &default=0;
    };
    
    type Info: record {
        syn_window_size: count &default=0;
        syn_opts: TCP_Options &default=TCP_Options();    
        synack_window_size: count &default=0;
        synack_opts: TCP_Options &default=TCP_Options();
        synack_delays: vector of count &default=vector();
        synack_done: bool &default=F;
        last_ts: double &default=0;
        rst_ts: double &default=0;
    };
}

redef record FINGERPRINT::Info += {
    ja4t: FINGERPRINT::JA4T::Info &default= Info();
};

redef record Conn::Info += {
    ja4t: string &log &default = "";
    ja4ts: string &log &default = "";
};

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
            offset += 2 + 40;
            break;
        } else {
            return opts;
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
            return opts;
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

# Быстрое формирование JA4T сразу после SYN
function do_ja4t_fast(c: connection) {
    if (c$fp$ja4t$syn_window_size > 0 && c$conn$ja4t == "") {
        c$conn$ja4t = fmt("%d", c$fp$ja4t$syn_window_size);
        c$conn$ja4t += FINGERPRINT::delimiter;
        c$conn$ja4t += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$syn_opts$option_kinds, "%d", "-");
        c$conn$ja4t += FINGERPRINT::delimiter;
        c$conn$ja4t += fmt("%d", c$fp$ja4t$syn_opts$max_segment_size);
        c$conn$ja4t += FINGERPRINT::delimiter;
        c$conn$ja4t += fmt("%d", c$fp$ja4t$syn_opts$window_scale);
        
        print fmt("JA4T: %s = %s", c$uid, c$conn$ja4t);
    }
}

# Быстрое формирование JA4TS
function do_ja4ts_fast(c: connection) {
    if (c$fp$ja4t$synack_window_size > 0 && c$conn$ja4ts == "") {
        c$conn$ja4ts = fmt("%d", c$fp$ja4t$synack_window_size);
        c$conn$ja4ts += FINGERPRINT::delimiter;
        c$conn$ja4ts += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$synack_opts$option_kinds, "%d", "-");
        c$conn$ja4ts += FINGERPRINT::delimiter;
        c$conn$ja4ts += fmt("%d", c$fp$ja4t$synack_opts$max_segment_size);
        c$conn$ja4ts += FINGERPRINT::delimiter;
        c$conn$ja4ts += fmt("%d", c$fp$ja4t$synack_opts$window_scale);
        
        # Добавляем задержки если есть
        if (|c$fp$ja4t$synack_delays| > 0) {
            c$conn$ja4ts += FINGERPRINT::delimiter;
            c$conn$ja4ts += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$synack_delays, "%d", "-");
            if (c$fp$ja4t$rst_ts > 0) {
                c$conn$ja4ts += fmt("-R%d", double_to_count(c$fp$ja4t$rst_ts - c$fp$ja4t$last_ts)/1000000);
            }
        }
        
        print fmt("JA4TS: %s = %s", c$uid, c$conn$ja4ts);
    }
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
    
    # Формируем JA4T сразу после SYN
    do_ja4t_fast(c);
    
    ConnThreshold::set_packets_threshold(c,1,F);
    ConnThreshold::set_packets_threshold(c,2,T);
}

event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) {
    # stop ts on any orig packet
    if(is_orig) {
        if(c?$fp) {
            c$fp$ja4t$synack_done = T;
            # Финальная запись JA4TS
            do_ja4ts_fast(c);
        }
        return;
    }
    
    if(!c?$fp || c$fp$ja4t$synack_done) {
        return;
    }
    
    local rph = get_current_packet_header();
    if (!rph?$tcp) {
        return;  
    }
    
    local ts = get_current_packet_timestamp();
    if (ts - c$fp$ja4t$last_ts > 120000000) {
        c$fp$ja4t$synack_done = T;
        do_ja4ts_fast(c);
        return;
    } 
    
    if (rph$tcp$flags & TH_RST != 0) {
        c$fp$ja4t$rst_ts = ts;
        c$fp$ja4t$synack_done = T;
        do_ja4ts_fast(c);
        return;
    } else if (rph$tcp$flags == (TH_SYN | TH_ACK)) {
    } else {
        return;
    }
    
    if (threshold == 1) {  # first synack
        c$fp$ja4t$synack_window_size = rph$tcp$win;
        c$fp$ja4t$synack_opts = get_tcp_options();
        # Формируем JA4TS сразу после первого SYN-ACK
        do_ja4ts_fast(c);
    } else {
        c$fp$ja4t$synack_delays += double_to_count(ts - c$fp$ja4t$last_ts)/1000000;
        # Обновляем JA4TS с новыми задержками
        c$conn$ja4ts = ""; # Сбрасываем для пересчета
        do_ja4ts_fast(c);
    }
    
    c$fp$ja4t$last_ts = ts;
    
    if (|c$fp$ja4t$synack_delays| < 10) {
        ConnThreshold::set_packets_threshold(c,threshold + 1,F);
    }
}

event connection_state_remove(c: connection) {
    # Финальная проверка - если что-то не записалось
    if (c?$fp) {
        do_ja4t_fast(c);
        do_ja4ts_fast(c);
    }
}
