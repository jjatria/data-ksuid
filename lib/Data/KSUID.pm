# ABSTRACT: KSUIDs for Perl
package Data::KSUID;

use strict;
use warnings;

our $VERSION = '0.001';

use parent 'Exporter';

our @EXPORT_OK = qw(
    create_ksuid
    ksuid_to_string
    string_to_ksuid
    is_ksuid_string
    time_of_ksuid
    payload_of_ksuid
    next_ksuid
    previous_ksuid
);

our %EXPORT_TAGS = ( all => \@EXPORT_OK );

use Carp ();
use Crypt::URandom ();
use Math::BigInt;
use Scalar::Util ();

# KSUID's epoch starts more recently so that the 32-bit
# number space gives a significantly higher useful lifetime
# of around 136 years from March 2017. This number (14e8)
# was picked to be easy to remember.
use constant EPOCH => 1_400_000_000;
use constant MAX_TIME => EPOCH + unpack( 'N', "\xff" x 4 );

use constant {
    MAX => "\xff" x 20,
    MIN => "\x00" x 20,
    MIN_STRING => '0' x 20,
    MAX_STRING => Math::BigInt->from_bytes("\xff" x 20)->to_base(62),
};

# Trusting private functions

my $safely_printed = sub {
    require B;
    defined $_[0]
        ? B::perlstring($_[0])
        : 'an undefined value';
};

my $ksuid_to_string  = sub { Math::BigInt->from_bytes($_[0])->to_base(62) };
my $string_to_ksuid  = sub { Math::BigInt->from_base($_[0], 62)->to_bytes };
my $time_of_ksuid    = sub { EPOCH + unpack 'N', substr( $_[0], 0, 4 )   };
my $payload_of_ksuid = sub { substr $_[0], 4, 20 };

my $next_ksuid = sub {
    my $k = shift;

    my $time = $k->$time_of_ksuid;
    my $data = $k->$payload_of_ksuid;

    # Overflow
    return create_ksuid( $time + 1, "\x00" x 16 )
        if $data eq ( "\xff" x 16 );

    my $next = Math::BigInt->from_bytes($data) + 1;
    create_ksuid( $time, join '', $next->to_bytes );
};

my $previous_ksuid = sub {
    my $k = shift;

    my $time = $k->$time_of_ksuid;
    my $data = $k->$payload_of_ksuid;

    # Overflow
    return create_ksuid( $time - 1, "\xff" x 16 )
        if $data eq ( "\x00" x 16 );

    my $prev = Math::BigInt->from_bytes($data) - 1;
    create_ksuid( $time, join '', $prev->to_bytes );
};

# Distrustful user-facing functions

sub create_ksuid {
    my ( $time, $payload ) = @_;

    if ( $time ) {
        Carp::croak 'Timestamp must be numeric'
            unless Scalar::Util::looks_like_number($time);

        Carp::croak "Timestamp must be between 0 and "
            . MAX_TIME . ", got $time instead"
            if $time < 0 || $time > MAX_TIME;
    }

    if ( $payload ) {
        my $length = length $payload;
        Carp::croak "KSUID payloads must have 16 bytes, got instead $length"
            if $length != 16;
    }

    $time    ||= time;
    $payload ||= Crypt::URandom::urandom(16);

    pack( 'N', $time - EPOCH ) . $payload;
}

sub ksuid_to_string {
    Carp::croak 'Expected a valid KSUID, got instead '
        . $_[0]->$safely_printed
        unless is_ksuid($_[0]);

    goto $ksuid_to_string;
}

sub string_to_ksuid {
    Carp::croak 'Expected a string KSUID, got instead '
        . $_[0]->$safely_printed
        unless is_ksuid_string($_[0]);

    goto $string_to_ksuid;
}

sub time_of_ksuid {
    Carp::croak 'Expected a valid KSUID, got instead '
        . $_[0]->$safely_printed
        unless is_ksuid($_[0]);

    goto $time_of_ksuid;
}

sub payload_of_ksuid {
    Carp::croak 'Expected a valid KSUID, got instead '
        . $_[0]->$safely_printed
        unless is_ksuid($_[0]);

    goto $payload_of_ksuid;
}

sub next_ksuid {
    Carp::croak 'Expected a valid KSUID, got instead '
        . $_[0]->$safely_printed
        unless is_ksuid($_[0]);

    goto $next_ksuid;
}

sub previous_ksuid {
    Carp::croak 'Expected a valid KSUID, got instead '
        . $_[0]->$safely_printed
        unless is_ksuid($_[0]);

    goto $previous_ksuid;
}

sub is_ksuid {
    return defined $_[0]
        && length $_[0] == 20
        && $_[0] ge MIN
        && $_[0] le MAX;
}

sub is_ksuid_string {
    return defined $_[0]
        && length $_[0] == 27
        && $_[0] ge MIN_STRING
        && $_[0] le MAX_STRING
        && $_[0] !~ /[^0-9A-Za-z]/;
}

## OO interface

use overload
    '""' => \&string,
    'eq' => sub { "$_[0]" eq "$_[1]" },
    'lt' => sub { "$_[0]" lt "$_[1]" },
    'gt' => sub { "$_[0]" gt "$_[1]" },
;

sub new {
    my $class = shift;
    my $self  = create_ksuid(@_);
    bless \$self, $class;
}

sub parse {
    my $class = shift;
    my $self  = string_to_ksuid(@_);
    bless \$self, $class;
}

sub bytes    { ${ $_[0] }                       }
sub payload  { $_[0]->bytes->$payload_of_ksuid  }
sub string   { $_[0]->bytes->$ksuid_to_string   }
sub time     { $_[0]->bytes->$time_of_ksuid     }

sub next {
    my $self = $_[0];
    my $next = $self->bytes->$next_ksuid;
    bless \$next, ref $self;
}

sub previous {
    my $self = $_[0];
    my $prev = $self->bytes->$previous_ksuid;
    bless \$prev, ref $self;
}

# Clean our namespace
delete $Data::KSUID::{$_} for qw(
    MAX_TIME
    EPOCH
);

1;
