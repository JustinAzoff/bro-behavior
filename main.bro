module behavior;

export {
    redef enum Log::ID += { LOG };

    type Type: enum {
        ## Dummy place-holder.
        UNKNOWN
    };

    type Info: record {
            ## Timestamp when the log line was finished and written.
            ts:         time    &log;

            ## The host
            host:       addr    &log;

            ## Behavior Type
            t:          Type    &log;

            ## Arbitrary count
            num:        count   &log &optional;

            ## Arbitrary string
            value:      string  &log &optional;
    };

    global log_behavior: event(rec: Info);
}

event bro_init()
{
    Log::create_stream(behavior::LOG, [$columns=Info, $ev=log_behavior]);
}
