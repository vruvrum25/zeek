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
        ja4ts_done: bool &default=F;  # Флаг для предотвращения дублирования JA4TS
        last_ts: double &default=0;
        rst_ts: double &default=0;
        first_synack_ts: double &default=0;  # Время первого SYN-ACK
    };
    
    # Отдельный лог для быстрого JA4T
    type FastJA4T: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        ja4t: string &log;
    };
    
    # Отдельный лог для умного JA4TS (один раз)
    type SmartJA4TS: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        ja4ts: string &log;
        delays_count: count &log;
        export_reason: string &log;  # Причина экспорта
    };
    
    redef enum Log::ID += { FAST_LOG, SMART_TS_LOG };
    global log_fast_ja4t: event(rec: FastJA4T);
    global log_smart_ja4ts: event(rec: SmartJA4TS);
    global fast_log_policy: Log::PolicyHook;
    global smart_ts_log_policy: Log::PolicyHook;
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

# Create the fast log streams
event zeek_init() &priority=5 {
    Log::create_stream(FINGERPRINT::JA4T::FAST_LOG,
        [$columns=FastJA4T, $ev=log_fast_ja4t, $path="ja4t_fast", $policy=fast_log_policy]);
    
    @if(FINGERPRINT::JA4TS_enabled)
    Log::create_stream(FINGERPRINT::JA4T::SMART_TS_LOG,
        [$columns=SmartJA4TS, $ev=log_smart_ja4ts, $path="ja4ts_smart", $policy=smart_ts_log_policy]);
    @endif
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
    
    print fmt("JA4T recorded: %s", c$uid);
}

# Умная функция для формирования ja4ts - записывается ТОЛЬКО ОДИН РАЗ
@if(FINGERPRINT::JA4TS_enabled)
function do_ja4ts_smart(c: connection) {
    if (!c?$fp || c$fp$ja4t$ja4ts_done || c$fp$ja4t$synack_window_size == 0) {
        return;
    }
    
    # Определяем, стоит ли записывать JA4TS сейчас
    local should_write = F;
    local reason = "";
    local now = get_current_packet_timestamp();
    
    # Условия для записи JA4TS:
    if (|c$fp$ja4t$synack_delays| >= 3) {
        # 1. Собрали достаточно задержек (≥3)
        should_write = T;
        reason = "enough_delays";
    } else if (c$fp$ja4t$synack_done) {
        # 2. Соединение закрывается
        should_write = T;
        reason = "connection_closing";
    } else if (c$fp$ja4t$rst_ts > 0) {
        # 3. RST пакет получен
        should_write = T;
        reason = "rst_received";
    } else if (c$fp$ja4t$first_synack_ts > 0 && (now - c$fp$ja4t$first_synack_ts) > 2000000) {
        # 4. Прошло >2 секунд с первого SYN-ACK
        should_write = T;
        reason = "timeout_2sec";
    } else if (|c$fp$ja4t$synack_delays| >= 1 && (now - c$fp$ja4t$last_ts) > 1000000) {
        # 5. Есть хотя бы 1 задержка и прошла 1 секунда с последнего пакета
        should_write = T;
        reason = "timeout_1sec";
    }
    
    if (!should_write) {
        return;
    }
    
    # Формируем ja4ts ОДИН РАЗ
    local ja4ts_value = fmt("%d", c$fp$ja4t$synack_window_size);
    ja4ts_value += FINGERPRINT::delimiter;
    ja4ts_value += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$synack_opts$option_kinds, "%d", "-");
    ja4ts_value += FINGERPRINT::delimiter;
    ja4ts_value += fmt("%d", c$fp$ja4t$synack_opts$max_segment_size);
    ja4ts_value += FINGERPRINT::delimiter;
    ja4ts_value += fmt("%d", c$fp$ja4t$synack_opts$window_scale);
    
    # Добавляем задержки если есть
    if (|c$fp$ja4t$synack_delays| > 0) {
        ja4ts_value += FINGERPRINT::delimiter;
        ja4ts_value += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$synack_delays, "%d", "-");
        if (c$fp$ja4t$rst_ts > 0) {
            ja4ts_value += fmt("-R%d", double_to_count(c$fp$ja4t$rst_ts - c$fp$ja4t$last_ts)/1000000);
        }
    }
    
    # ЗАПИСЫВАЕМ ТОЛЬКО ОДИН РАЗ в умный лог
    local smart_ts_record = SmartJA4TS($ts=network_time(), $uid=c$uid, $id=c$id, 
                                       $ja4ts=ja4ts_value, $delays_count=|c$fp$ja4t$synack_delays|,
                                       $export_reason=reason);
    Log::write(FINGERPRINT::JA4T::SMART_TS_LOG, smart_ts_record);
    
    # Также записываем в conn для совместимости
    c$conn$ja4ts = ja4ts_value;
    c$fp$ja4t$ja4ts_done = T;  # ВАЖНО: помечаем как обработанный
    
    print fmt("JA4TS recorded ONCE: %s, reason: %s, delays: %d", 
              c$uid, reason, |c$fp$ja4t$synack_delays|);
}
@endif

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
            # Последняя попытка записать JA4TS при закрытии
            @if(FINGERPRINT::JA4TS_enabled)
            do_ja4ts_smart(c);
            @endif
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
        @if(FINGERPRINT::JA4TS_enabled)
        do_ja4ts_smart(c);
        @endif
        return;
    } 
    if (rph$tcp$flags & TH_RST != 0) {
        c$fp$ja4t$rst_ts = ts;
        c$fp$ja4t$synack_done = T;
        @if(FINGERPRINT::JA4TS_enabled)
        do_ja4ts_smart(c);
        @endif
        return;
    } else if (rph$tcp$flags == (TH_SYN | TH_ACK)) {
    } else {
        return;
    }
    if (threshold == 1) {  # first synack
        c$fp$ja4t$synack_window_size = rph$tcp$win;
        c$fp$ja4t$synack_opts = get_tcp_options();
        c$fp$ja4t$first_synack_ts = ts;  # Запоминаем время первого SYN-ACK
        # НЕ записываем JA4TS сразу - ждем больше данных
    } else {
        # Записываем задержку
        c$fp$ja4t$synack_delays += double_to_count(ts - c$fp$ja4t$last_ts)/1000000;
        # Проверяем, стоит ли записать JA4TS сейчас
        @if(FINGERPRINT::JA4TS_enabled)
        do_ja4ts_smart(c);
        @endif
    }
    c$fp$ja4t$last_ts = ts;
    
    if (|c$fp$ja4t$synack_delays| == 10) {
        # Достигли максимума задержек - финальная запись
        @if(FINGERPRINT::JA4TS_enabled)
        if (!c$fp$ja4t$ja4ts_done) {
            c$fp$ja4t$synack_done = T;
            do_ja4ts_smart(c);
        }
        @endif
        return;
    } 
    @if(FINGERPRINT::JA4TS_enabled) 
        ConnThreshold::set_packets_threshold(c,threshold + 1,F);
    @endif
}

event connection_state_remove(c: connection) {
    # Оба отпечатка уже выведены в быстрые логи
    # Последняя попытка для JA4TS если не записан
    @if(FINGERPRINT::JA4TS_enabled) 
    if (c?$fp && !c$fp$ja4t$ja4ts_done && c$fp$ja4t$synack_window_size > 0) {
        do_ja4ts_smart(c);
    }
    @endif
}
