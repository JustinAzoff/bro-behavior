@load ../main

module behavior;

export {
    redef enum behavior::Type += {
        TCP_INBOUND,
        TCP_OUTBOUND,
    };
    
    global seen_inbound: set[addr] &create_expire=1day &synchronized;
    global seen_outbound: set[addr] &create_expire=1day &synchronized;
    
    global threshold_vector: vector of double = vector(1,10,100,1000,10000,100000,1000000) &redef;
}

event bro_init()
{
    local ro: SumStats::Reducer = [$stream="tcp.outbound", $apply=set(SumStats::SUM)];
    local ri: SumStats::Reducer = [$stream="tcp.inbound", $apply=set(SumStats::SUM)];
    SumStats::create([$name="count-tcp-outbound",
                      $epoch=1days,
                      $reducers=set(ro),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                        {
                        return result["tcp.outbound"]$sum;
                        },
                      $threshold_series=threshold_vector,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["tcp.outbound"];
                        Log::write(LOG, [$ts=network_time(), $host=key$host, $t=TCP_OUTBOUND, $num=r$num]);
                        }]);

    SumStats::create([$name="count-tcp-inbound",
                      $epoch=1days,
                      $reducers=set(ri),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                        {
                        return result["tcp.inbound"]$sum;
                        },
                      $threshold_series=threshold_vector,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["tcp.outbound"];
                        Log::write(LOG, [$ts=network_time(), $host=key$host, $t=TCP_INBOUND, $num=r$num]);
                        }]);
}



event connection_established(c: connection)
{
    local id = c$id;

    if ( c$orig$state != TCP_ESTABLISHED ||
          c$resp$state != TCP_ESTABLISHED ) {
        return;
    }

    if( Site::is_local_addr(id$orig_h) ) {
        SumStats::observe("tcp.outbound", [$host=id$orig_h], [$num=1]);
    }

    if( Site::is_local_addr(id$resp_h) ) {
        SumStats::observe("tcp.inbound", [$host=id$resp_h], [$num=1]);
    }

}
