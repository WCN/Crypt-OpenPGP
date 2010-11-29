package Crypt::OpenPGP::Signature::SubPacket::Features;
use strict;

use base 'Crypt::OpenPGP::Signature::SubPacket';

use vars qw( %FEATURES );
%FEATURES = (
  0x01    => { 'name'            => 'Modification Detection',
               'subpacket_types' => [ 18, 19 ] },
);

sub new {
  my $class = shift;
  my $self  = $class->SUPER::new(@_);
  $self->{'type'} = 30;
  $self;
}

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

  my @lst;
  foreach my $id (keys %FEATURES) {
    if(($self->{'data'} || 0) & $id) {
      push(@lst, $FEATURES{$id}->{'name'});
    }
  }
  return __PACKAGE__.": '" . join("', '", @lst) . "'\n";
}

sub supports_modification_detection {
  my $self = shift;
  if(@_) {
    if($_[0]) {
      $self->{'data'} = ($self->{'data'} || 0) | 0x01;
    }
    else {
      $self->{'data'} = ($self->{'data'} || 0) & ~ 0x01;
    }
  }
  else {
    return ($self->{'data'} || 0) & 0x01 ? 1 : 0;
  }
}

1;
__END__

=head1 NAME

 Crypt::OpenPGP::Signature::Subpacket::Features

=head1 DESCRIPTION

OpenPGP class to allow access to features packets within signatures.
These packets basically specify what features a recipient supports.

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

=head2 supports_modification_detection()

Returns true if this packet specifies support for modification
detection, false otherwise.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::OpenPGP manpage for author, copyright, and
license information.

=cut

