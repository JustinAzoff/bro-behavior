@load ../main

module behavior;

export {
    redef enum behavior::Type += {
        TCP_INBOUND,
        TCP_OUTBOUND,
    };
    
    global seen_inbound: set[addr] &create_expire=1day &synchronized;
    global seen_outbound: set[addr] &create_expire=1day &synchronized;
};


event connection_established(c: connection)
{
    local id = c$id;

    if !( c$orig$state == TCP_ESTABLISHED &&
          c$resp$state == TCP_ESTABLISHED ) {
        return;
    }

    if(id$orig_h !in seen_outbound && Site::is_local_addr(id$orig_h) {
        add seen_outbound[id$orig_h];
        Log::write(LOG, [$ts=network_time(), $host=$id$resp_h, $t=TCP_OUTBOUND);
    }
    if(id$resp_h !in seen_inbound && Site::is_local_addr(id$resp_h) {
        add seen_inbound[id$resp_h];
        Log::write(LOG, [$ts=network_time(), $host=$id$resp_h, $t=TCP_INBOUND);
    }
}
