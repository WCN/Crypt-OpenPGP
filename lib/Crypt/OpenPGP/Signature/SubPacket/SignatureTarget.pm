package Crypt::OpenPGP::Signature::SubPacket::SignatureTarget;
use strict;

use base 'Crypt::OpenPGP::Signature::SubPacket';

sub read_data {
  my($self, $buf) = @_;
  $self->{'pk_alg'}   = $buf->get_int8;
  $self->{'hash_alg'} = $buf->get_int8;
  my $size = Crypt::OpenPGP::Digest->alg_size( $self->{'pk_alg'} );
  $self->{'hash'}     = $buf->get_bytes( $size ) if $size;
}

sub write_data {
  my($self, $buf) = @_;
  $buf->put_int8($self->{'pk_alg'});
  $buf->put_int8($self->{'hash_alg'});
  $buf->append( $self->{'hash'} );
}

sub display {
  my $self  = shift;
  my $alg  = Crypt::OpenPGP::Key->alg($self->{'pk_alg'});
  my $hash = Crypt::OpenPGP::Digest->alg($self->{'hash_alg'});
  my $data = unpack("H*", $self->{'hash'});
  return __PACKAGE__.": '$alg', '$hash' => '$data'\n";
}

sub pk_alg {
  my $self = shift;
  if(@_) {
    $self->{'pk_alg'} = $_[0];
  }
  else {
    return $self->{'pk_alg'};
  }
}

sub hash_alg {
  my $self = shift;
  if(@_) {
    $self->{'hash_alg'} = $_[0];
  }
  else {
    return $self->{'hash_alg'};
  }
}

sub hash {
  my $self = shift;
  if(@_) {
    $self->{'hash'} = $_[0];
  }
  else {
    return $self->{'hash'};
  }
}

1;
__END__

=head1 NAME

 Crypt::OpenPGP::Signature::Subpacket::SignatureTarget

=head1 DESCRIPTION

OpenPGP class to allow access to signature target packets. These
packets basically specify a specific target signature that a signature
refers to.

=head1 METHODS

=head2 new()

Creates a new instance of this class.

=head2 read_data($buf)

Reads data out of the buffer.

=head2 write($buf)

Write a serialized representation of this class to the buffer.

=head2 display()

Returns an array of strings, describing the properties of an
instance of this class.

=head2 pk_alg

Returns the public key algorithm used. Can be looked up via the
L<Crypt::OpenPGP::Key> class.

=head2 hash_alg

Returns the hash digest algorithm used. Can be looked up via the
L<Crypt::OpenPGP::Key> class.

=head2 hash

Returns the hash value.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::OpenPGP manpage for author, copyright, and
license information.

=cut

