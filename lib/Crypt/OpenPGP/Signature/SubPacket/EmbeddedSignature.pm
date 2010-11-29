package Crypt::OpenPGP::Signature::SubPacket::EmbeddedSignature;
use strict;

use base 'Crypt::OpenPGP::Signature::SubPacket';

sub new {
  my $class = shift;
  my $self  = $class->SUPER::new(@_);
  $self->{'type'} = 32;
  $self;
}

sub read_data {
  my($self, $buf) = @_;
  my $sig = Crypt::OpenPGP::Signature->parse($buf);
  $self->{'embedded_sig'} = $sig;
}

sub write_data {
  my($self, $buf) = @_;
  $buf->append( $self->{'embedded_sig'}->save() );
}

sub display {
  my $self  = shift;
  my @lines = (__PACKAGE__ . ":\n");
  my @tmp = $self->{'embedded_sig'}->display();
  foreach my $line (@tmp) {
    push(@lines, "  $line");
  }
  return @lines;
}

sub embedded_signature {
  my $self = shift;
  if(@_) {
    $self->{'embedded_sig'} = $_[0];
  }
  else {
    return $self->{'embedded_sig'};
  }
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

=head2 embedded_signature

Accessor for the embedded signature object.

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

