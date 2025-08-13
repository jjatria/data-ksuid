#!/usr/bin/env perl

use Test2::V0 -target => 'Data::KSUID';

is [ sort keys %Data::KSUID:: ], [qw|
    (""
    ((
    (cmp
    BEGIN
    EXPORT_OK
    EXPORT_TAGS
    MAX
    MAX_STRING
    MIN
    MIN_STRING
    VERSION
    __ANON__
    bytes
    create_ksuid
    create_ksuid_string
    import
    is_ksuid
    is_ksuid_string
    ksuid_to_string
    new
    next
    next_ksuid
    parse
    payload
    payload_of_ksuid
    previous
    previous_ksuid
    string
    string_to_ksuid
    time
    time_of_ksuid
|] => 'No unexpected methods in namespace';

done_testing;
