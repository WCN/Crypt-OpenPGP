package Crypt::OpenPGP::Signature::SubPacket::NotationData;
use strict;

use base 'Crypt::OpenPGP::Signature::SubPacket';

sub read_data {
  my($self, $buf) = @_;
  $self->{'flags'} = $buf->get_int32;
  $self->{'name'}  = $buf->get_bytes( $buf->get_int16 );
  $self->{'value'} = $buf->get_bytes( $buf->get_int16 );
}

sub write_data {
  my($self, $buf) = @_;
  $buf->put_int32( $self->{'flags'} );
  $buf->put_int16( length($self->{'name'}) );
  $buf->put_bytes( $self->{'name'} );
  $buf->put_int16( length($self->{'value'}) );
  $buf->put_bytes( $self->{'value'} );
}

sub display {
  my $self = shift;
  return ( __PACKAGE__ . ": readable: ".$self->human_readable."\n",
           "  name:  '".$self->name."'\n",
           "  value: '".$self->value."'\n");
}

sub flags {
  my $self = shift;
  if(@_) {
    $self->{'flags'} = shift;
    return $self;
  }
  else {
    return $self->{'flags'};
  }
}

sub human_readable {
  my $self = shift;
  return ($self->{'flags'} || 0) & 0x80 ? 1 : 0;
}

sub name {
  my $self = shift;
  if(@_) {
    $self->{'name'} = shift;
    return $self;
  }
  else {
    return $self->{'name'};
  }
}

sub value {
  my $self = shift;
  if(@_) {
    $self->{'value'} = shift;
    return $self;
  }
  else {
    return $self->{'value'};
  }
}

1;
__END__

=head1 NAME

 Crypt::OpenPGP::Signature::Subpacket::NotationData

=head1 DESCRIPTION

OpenPGP class to allow access to Notation Data within signatures. This
is basically a key and a value, with a flag to say if it's human
readable or not.

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

=head2 flags()

Get or set the flags.

=head2 name()

Get or set the name

=head2 value()

Get or set the value.

=head2 human_readable()

Returns true if the name and value are human readable.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::OpenPGP manpage for author, copyright, and
license information.

=cut

