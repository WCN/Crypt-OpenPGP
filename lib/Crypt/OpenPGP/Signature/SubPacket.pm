package Crypt::OpenPGP::Signature::SubPacket;
use strict;

use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

use vars qw( %SUBPACKET_TYPES %SIGNATURE_TYPES );
%SUBPACKET_TYPES = (
    2  => { name => 'Signature creation time',
            r    => sub { $_[0]->get_int32 },
            w    => sub { $_[0]->put_int32($_[1]) } },

    3  => { name => 'Signature expiration time',
            r    => sub { $_[0]->get_int32 },
            w    => sub { $_[0]->put_int32($_[1]) } },

    4  => { name => 'Exportable certification',
            r    => sub { $_[0]->get_int8 },
            w    => sub { $_[0]->put_int8($_[1]) } },

    5  => { name => 'Trust signature',
            r    => sub { $_[0]->get_int8 },
            w    => sub { $_[0]->put_int8($_[1]) } },

    6  => { name => 'Regular expression',
            r    => sub { $_[0]->bytes },
            w    => sub { $_[0]->append($_[1]) } },

    7  => { name => 'Revocable',
            r    => sub { $_[0]->get_int8 },
            w    => sub { $_[0]->put_int8($_[1]) } },

    9  => { name => 'Key expiration time',
            r    => sub { $_[0]->get_int32 },
            w    => sub { $_[0]->put_int32($_[1]) } },

    10 => { name => 'Additional Decryption Key',
            r    => sub {
                        { class => $_[0]->get_int8,
                          alg_id => $_[0]->get_int8,
                          fingerprint => $_[0]->get_bytes(20) } },
            w    => sub {
                        $_[0]->put_int8($_[1]->{class});
                        $_[0]->put_int8($_[1]->{alg_id});
                        $_[0]->put_bytes($_[1]->{fingerprint}, 20) } },

    11 => { name => 'Preferred symmetric algorithms',
            r    => sub { [ unpack 'C*', $_[0]->bytes ] },
            w    => sub { $_[0]->append(pack 'C*', @{ $_[1] }) } },

    12 => { name => 'Revocation key',
            r    => sub {
                        { class => $_[0]->get_int8,
                          alg_id => $_[0]->get_int8,
                          fingerprint => $_[0]->get_bytes(20) } },
            w    => sub {
                        $_[0]->put_int8($_[1]->{class});
                        $_[0]->put_int8($_[1]->{alg_id});
                        $_[0]->put_bytes($_[1]->{fingerprint}, 20) } },

    16 => { name => 'Issuer key ID',
            r    => sub { $_[0]->get_bytes(8) },
            w    => sub { $_[0]->put_bytes($_[1], 8) } },

    20 => { name => 'Notation data',
            pkg  => 'Crypt::OpenPGP::Signature::SubPacket::NotationData' },
    21 => { name => 'Preferred hash algorithms',
            r    => sub { [ unpack 'C*', $_[0]->bytes ] },
            w    => sub { $_[0]->put_bytes(pack 'C*', @{ $_[1] }) } },

    22 => { name => 'Preferred compression algorithms',
            r    => sub { [ unpack 'C*', $_[0]->bytes ] },
            w    => sub { $_[0]->put_bytes(pack 'C*', @{ $_[1] }) } },

    23 => { name => 'Key server preferences',
            r    => sub { $_[0]->bytes },
            w    => sub { $_[0]->append($_[1]) } },

    24 => { name => 'Preferred key server',
            r    => sub { $_[0]->bytes },
            w    => sub { $_[0]->append($_[1]) } },

    25 => { name => 'Primary user ID',
            r    => sub { $_[0]->get_int8 },
            w    => sub { $_[0]->put_int8($_[1]) } },

    26 => { name => 'Policy URL',
            r    => sub { $_[0]->bytes },
            w    => sub { $_[0]->append($_[1]) } },

    27 => { name => 'Key flags',
            pkg  => 'Crypt::OpenPGP::Signature::SubPacket::KeyFlags' },
    28 => { name => 'Signer\'s user ID',
            r    => sub { $_[0]->bytes },
            w    => sub { $_[0]->append($_[1]) } },

    29 => { name => 'Reason for revocation',
            r    => sub {
                        { code => $_[0]->get_int8,
                          reason => $_[0]->get_bytes($_[0]->length -
                                                     $_[0]->offset) } },
            w    => sub {
                          $_[0]->put_int8($_[1]->{code});
                          $_[0]->put_bytes($_[1]->{reason}) } },
    30 => { name => 'Features',
            pkg  => 'Crypt::OpenPGP::Signature::SubPacket::Features' },
    31 => { name => 'Signature Target',
            pkg  => 'Crypt::OpenPGP::Signature::SubPacket::SignatureTarget' },
    32 => { name => 'Embedded Signature',
            pkg  => 'Crypt::OpenPGP::Signature::SubPacket::EmbeddedSignature' },

);

sub new {
  my($class, $hash) = @_;
  bless { %{ $hash || {} } }, $class;
}

sub parse {
    my $class = shift;
    my($buf) = @_;
    my $sp = $class->new;
    my $tag = $buf->get_int8;
    $sp->{critical} = $tag & 0x80;
    $sp->{type} = $tag & 0x7f;
    $buf->bytes(0, 1, '');   ## Cut off tag byte
    $buf->{offset} = 0;

    my $ref = $SUBPACKET_TYPES{$sp->{type}};
    if($ref && (my $pkg = $ref->{'pkg'})) {
      eval "require $pkg"; die $@ if $@;
      bless($sp, $pkg);
    }
    $sp->read_data($buf);
    $sp;
}

sub read_data {
  my($sp, $buf) = @_;
  my $ref = $SUBPACKET_TYPES{$sp->{type}};
  $sp->{data} = $ref->{r}->($buf) if $ref && $ref->{r};
}

sub save {
    my $sp = shift;
    my $buf = Crypt::OpenPGP::Buffer->new;
    my $tag = $sp->{type};
    $tag |= 0x80 if $sp->{critical};
    $buf->put_int8($tag);
    $sp->write_data($buf);
    $buf->bytes;
}

sub write_data {
  my($sp, $buf) = @_;
  my $ref = $SUBPACKET_TYPES{$sp->{type}};
  $ref->{w}->($buf, $sp->{data}) if $ref && $ref->{w};
}

sub data {
  my $sp = shift;
  return $sp->{'data'};
}

sub data_hex {
  my $sp = shift;
  return uc unpack('H*', $sp->{'data'});
}

sub type {
  my $sp = shift;
  return $sp->{'type'};
}

sub name {
  my $sp = shift;
  return $SUBPACKET_TYPES{ $sp->type }->{'name'},
}

sub critical {
  my $sp = shift;
  return $sp->{'critical'};
}


sub display {
  my $sp = shift;
  my @lines;

  my $str = sprintf("%s: type: %d, (%s) critical: %d\n",
                    __PACKAGE__, $sp->type, $sp->name, $sp->critical);
  push(@lines, $str);

  my $val = $sp->{'data'} // "";
  if(ref($val) eq "HASH") {
    foreach my $key (keys %$val) {
      push(@lines, "    '$key' => '".$val->{$key}."'\n");
    }
  }
  elsif(ref($val) eq "ARRAY") {
    push(@lines, "    values: '".join("', '", @$val)."'\n");
  }
  elsif($val =~ m/^[0-9a-zA-Z_.-]+$/) {
    push(@lines, "    value: '$val'\n");
  }
  else {
    push(@lines, "    value: '".$sp->data_hex."'\n");
  }
  return @lines;
}

1;
__END__

=head1 NAME

Crypt::OpenPGP::Signature::SubPacket

=head1 DESCRIPTION

OpenPGP class allowing access to subpackets within a signature, and
various properties of them.

=head1 METHODS

=head2 new()

Create a new instance of this class

=head1 parse($buf)

Initialize a new instance of this class (or a subclass) based on the
data in the buffer.

=head1 read_data($buf)

Reads subpacket type specific data out of the buffer.

=head1 save()

Returns a serialized representation of this object.

=head2 write_data($buf)

Write subpacket specific data into the specified buffer.

=head2 data()

Returns the subpacket specific data.

=head2 type()

Returns the numeric subpacket type.

=head2 name()

Returns a human readable version of the type.

=head2 critical

Returns a boolean flag - if set, it means that the originator of this
data would prefer you to reject the entire signature if you don't
understand this subpacket, rather than ignoring it.

=head2 display()

Return an arrayref of strings, describing this subpacket.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::OpenPGP manpage for author, copyright, and
license information.

=cut
