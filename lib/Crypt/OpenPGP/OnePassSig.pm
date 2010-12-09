package Crypt::OpenPGP::OnePassSig;
use strict;

sub new {
    my $class = shift;
    my $sig   = bless { }, $class;
    $sig->init(@_);
}

sub init {
    my($self, $sig) = @_;
    return $self unless $sig;
    $self->{'version'}   = 3;
    $self->{'type'}      = $sig->type;
    $self->{'hash_alg'}  = $sig->hash_alg;
    $self->{'pk_alg'}    = $sig->pk_alg;
    $self->{'key_id'}    = $sig->key_id;
    $self->{'nested'}    = 1;   ## TODO - not supported yet
    return $self;
}

sub parse {
    my $class = shift;
    my($buf) = @_;
    my $onepass = $class->new;
    $onepass->{version} = $buf->get_int8;
    $onepass->{type} = $buf->get_int8;
    $onepass->{hash_alg} = $buf->get_int8;
    $onepass->{pk_alg} = $buf->get_int8;
    $onepass->{key_id} = $buf->get_bytes(8);
    $onepass->{nested} = $buf->get_int8;
    $onepass;
}

sub save {
  my $self = shift;
  my $buf  = Crypt::OpenPGP::Buffer->new;
  $buf->put_int8($self->version);
  $buf->put_int8($self->type);
  $buf->put_int8($self->hash_alg);
  $buf->put_int8($self->pk_alg);
  $buf->put_bytes($self->key_id, 8);
  $buf->put_int8($self->nested);
  return $buf->bytes;
}

sub version {
    my $self = shift;
    return $self->{'version'};
}

sub type {
    my $self = shift;
    return $self->{'type'};
}

sub type_name {
    my $self = shift;
    return Crypt::OpenPGP::Signature->type_name($self->type);
}

sub hash_alg {
    my $self = shift;
    return $self->{'hash_alg'};
}

sub hash_alg_name {
    my $sig  = shift;
    my $hash = Crypt::OpenPGP::Digest->alg($sig->{'hash_alg'});
    return $hash;
}

sub pk_alg {
    my $self = shift;
    return $self->{'pk_alg'};
}

sub pk_alg_name {
    my $sig  = shift;
    my $alg  = Crypt::OpenPGP::Key->alg($sig->{'pk_alg'});
    return $alg;
}

sub key_id {
    my $self = shift;
    return $self->{'key_id'};
}

sub key_id_hex {
    my $self = shift;
    return uc unpack('H*', $self->key_id);
}

sub nested {
    my $self = shift;
    return $self->{'nested'};
}

sub display {
    my $self = shift;
    my $str = sprintf("%s: version %d, type %d (%s), algo: %s, %s\n",
                      __PACKAGE__, $self->version, $self->type,
                      $self->type_name, $self->pk_alg_name,
                      $self->hash_alg_name);
    return $str;
}

1;
__END__

=head1 NAME

Crypt::OpenPGP::OnePassSig - One-Pass Signature packet

=head1 DESCRIPTION

I<Crypt::OpenPGP::OnePassSig> implements a PGP One-Pass Signature
packet, a packet that precedes the signature data and contains
enough information to allow the receiver of the signature to begin
computing the hashed data. Standard signature packets always come
I<before> the signed data, which forces receivers to backtrack to
the beginning of the message--to the signature packet--to add on
the signature trailer data. The one-pass signature packet allows
the receive to start computing the hashed data while reading the
data packet, then continue on sequentially when it reaches the
signature packet.

=head1 METHODS

=head2 my $onepass = Crypt::OpenPGP::OnePassSig->parse($buffer)

Given the I<Crypt::OpenPGP::Buffer> object buffer, which should
contain a one-pass signature packet, parses the object from the
buffer and returns the object.

=head2 my $onepass = Crypt::OpenPGP::OnePassSig->new($sig)

Accepts an L<Crypt::OpenPGP::Signature> object, and returns a new
instance of this class.

=head2 $sig->key_id 
 
Returns the ID of the key that created the signature. 
 
=head2 $sig->key_id_hex 
 
Returns the ID of the key that created the signature in readable form. 
 
=head2 $sig->version 
 
The signature version. 

=head2 type

Returns the "type" of signature that this is, eg "0" means "signature
of a binary document".

=head2 type_name

Returns a human readable string describing the type of signature that
this is. 15 signature types are defined by the OpenPGP standard, for
example "Generic Certification of User Id and Public Key". See RFC
4880 for more details.

=head2 $sig->hash_alg 
 
Returns the hash algorithm id for this signature. These (numeric) ids 
can be looked up via L<Crypt::OpenPGP::Digest>. 
 
=head2 $sig->hash_alg_name 
 
Returns a name for the hash algorithm. 
 
=head2 $sig->pk_alg 
 
Returns the public key algorithm id for this signature. These ids can 
be looked up via L<Crypt::OpenPGP::Key>. 
 
=head2 $sig->pk_alg_name 
 
Returns a name for the public key algorithm. 

=head2 $sig->display

Returns a human-readable description of this packet.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::OpenPGP manpage for author, copyright, and
license information.

=cut
