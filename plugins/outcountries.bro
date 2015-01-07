@load ../main

module behavior;

export {
    redef enum behavior::Type += {
        TCP_OUTBOUND_CC,
    };
    
    global seen_outbound_cc: set[addr, string] &create_expire=1day &synchronized;
}

function do_check(c: connection)
{
    local id = c$id;

    if( !Site::is_local_addr(id$orig_h) ) {
        return;
    }
    local loc = lookup_location(c$id$resp_h);
    if(!loc?$country_code) {
        return;
    }
    local cc = loc$country_code;

    if([id$orig_h, cc] !in seen_outbound_cc && Site::is_local_addr(id$orig_h)) {
        add seen_outbound_cc[id$orig_h, cc];
        Log::write(LOG, [$ts=network_time(), $host=id$orig_h, $t=TCP_OUTBOUND_CC, $value=cc]);
    }
}

event connection_established(c: connection)
{
    if( c$orig$state == TCP_ESTABLISHED &&
        c$resp$state == TCP_ESTABLISHED ) {
        do_check(c);
    }
}
