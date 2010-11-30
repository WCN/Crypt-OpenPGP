package Crypt::OpenPGP::Signature::SubPacket::KeyFlags;
use strict;

use base 'Crypt::OpenPGP::Signature::SubPacket';

use vars qw( %FEATURES );
%FEATURES = (
  'can_certify_other_keys'     => 0x01,
  'can_sign_data'              => 0x02,
  'can_encrypt_communications' => 0x04,
  'can_encrypt_storage'        => 0x08,
  'private_key_may_be_split'   => 0x10,
  'can_use_authentication'     => 0x20,
  'private_key_multiple_users' => 0x80,
);

sub new { bless { 'type' => 27, 'data' => 0 }, $_[0] }

sub read_data {
  my($self, $buf) = @_;
  $self->{'data'} = $buf->get_int8;
}

sub write_data {
  my($self, $buf) = @_;
  $buf->put_int8( $self->{'data'} );
}

sub display {
  my $self = shift;
  return ( __PACKAGE__.": '".$self->{'data'}."':\n",
           map { "    $_: '".$self->$_."'\n" } sort keys %FEATURES );
}

sub flags {
  my $self = shift;
  my %out  = ();
  foreach my $key (keys %FEATURES) {
    my $val = $FEATURES{$key};
    $out{ $key } = ($self->{'data'} & $val) ? 1 : 0;
  }
  return \%out;
}

{
  no strict 'refs';
  foreach my $meth (keys %FEATURES) {
    *$meth = sub {
      my $self = shift;
      if(@_) {
        if($_[0]) {
          $self->{'data'} = $self->{'data'} | $FEATURES{$meth};
        }
        else {
          $self->{'data'} = $self->{'data'} & ~ $FEATURES{$meth};
        }
      }
      else {
        return $self->{'data'} & $FEATURES{$meth} ? 1 : 0;
      }
    };
  }
}

1;
__END__

=head1 NAME

 Crypt::OpenPGP::Signature::Subpacket::KeyFlags

=head1 DESCRIPTION

OpenPGP class to allow access to key flags packets within signatures.
These packets basically specify what uses an issuer wants a key to be
used for.

=head1 METHODS

=head2 new()

Creates a new instance of this class.

=head2 read_data($buf)

Reads data out of the buffer.

=head2 write($buf)

Write a serialized representation of this class to the buffer.

=head2 display()

Returns an arrayref of strings, describing the properties of an
instance of this class.

=head2 can_certify_other_keys

Indicates if this key can be used to certify other keys.

=head2 can_sign_data

Indicates if this key can be used for signing data.

=head2 can_encrypt_communications

Indicates if this key can be used to encrypt communications.

=head2 can_encrypt_storage

Indicates if this key can be used to encrypt data in storage.

=head2 private_key_may_be_split

Indicates that the private components of this key may have been split
by a secret sharing mechanism.

=head2 can_use_authentication

Indicates that this key may be used for authentication.

=head2 private_key_multiple_users

Indicates that mutliple people may be in possession of the private key

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::OpenPGP manpage for author, copyright, and
license information.

=cut

