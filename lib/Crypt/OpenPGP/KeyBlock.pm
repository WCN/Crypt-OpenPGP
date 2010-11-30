package Crypt::OpenPGP::KeyBlock;
use strict;

use Crypt::OpenPGP::PacketFactory;

sub primary_uid {
  my $kb  = shift;
  return $kb->{'_primary_uid'} if $kb->{'_primary_uid'};
  my @sigs = sort { $a->timestamp <=> $b->timestamp } $kb->all_self_sigs;
  $kb->{'_primary_uid'} = $sigs[-1]->uid;
  return $kb->{'_primary_uid'};
}

sub key { $_[0]->get('Crypt::OpenPGP::Certificate')->[0] }
sub subkey { $_[0]->get('Crypt::OpenPGP::Certificate')->[1] }

sub encrypting_key {
    my $kb = shift;
    my $keys = $kb->get('Crypt::OpenPGP::Certificate');
    return unless $keys && @$keys;
    for my $key (@$keys) {
        return $key if $key->can_encrypt;
    }
}

sub signing_key {
    my $kb = shift;
    my $keys = $kb->get('Crypt::OpenPGP::Certificate');
    return unless $keys && @$keys;
    for my $key (@$keys) {
        return $key if $key->can_sign;
    }
}

sub key_by_id { $_[0]->{keys_by_id}->{$_[1]} ||
                $_[0]->{keys_by_short_id}->{$_[1]} }

sub new {
    my $class = shift;
    my $kb = bless { }, $class;
    $kb->init(@_);
}

sub init {
    my $kb = shift;
    $kb->{pkt} = { };
    $kb->{order} = [ ];
    $kb->{keys_by_id} = { };
    $kb;
}

sub add {
    my($kb, $pkt) = @_;
    push @{ $kb->{pkt}->{ ref($pkt) } }, $pkt;
    push @{ $kb->{order} }, $pkt;

    if (ref($pkt) eq 'Crypt::OpenPGP::Certificate') {
        my $kid = $pkt->key_id;
        $kb->{keys_by_id}{ $kid } = $pkt;
        $kb->{keys_by_short_id}{ substr $kid, -4, 4 } = $pkt;
    }
    if (ref($pkt) eq 'Crypt::OpenPGP::Signature') {
        if($kb->{pkt}->{'Crypt::OpenPGP::UserID'}) {
            my $uid = $kb->{pkt}->{'Crypt::OpenPGP::UserID'}->[-1];
            $pkt->uid($uid->id);
        }
    }
    $pkt->keyblock($kb);
    $kb;
}

sub get { $_[0]->{pkt}->{ $_[1] } }

sub save {
    my $kb = shift;
    Crypt::OpenPGP::PacketFactory->save( @{ $kb->{order} } );
}

sub save_armoured {
    my $kb = shift;
    require Crypt::OpenPGP::Armour;
    Crypt::OpenPGP::Armour->armour(
                Data => $kb->save,
                Object => 'PUBLIC KEY BLOCK'
        );
}

sub display {
    my $kb = shift;
    my @lines;

    push(@lines, __PACKAGE__ . ":\n");
    foreach my $pkt (@{ $kb->{'order'} }) {
        my @tmp = $pkt->display();
        push(@lines, map { "    $_" } @tmp);
    }
    return @lines;
}

sub all_user_ids {
  my $kb  = shift;
  my @out = ();
  unless($kb->{pkt} && $kb->{pkt}->{'Crypt::OpenPGP::UserID'}) {
    return;
  }
  foreach my $uid (@{ $kb->{pkt}->{'Crypt::OpenPGP::UserID'} }) {
    push(@out, $uid->id);
  }
  return @out;
}

sub all_keys {
  my $kb = shift;
  return @{ $kb->{'pkt'}->{'Crypt::OpenPGP::Certificate'} };
}

sub all_signatures {
  my $kb = shift;
  return @{ $kb->{'pkt'}->{'Crypt::OpenPGP::Signature'} };
}

sub all_self_sigs {
  my $kb = shift;
  my(@out, %keys);

  foreach my $cert (@{ $kb->{'pkt'}->{'Crypt::OpenPGP::Certificate'} }) {
    $keys{ $cert->key_id_hex } = $cert;
  }
  foreach my $sig (@{ $kb->{'pkt'}->{'Crypt::OpenPGP::Signature'} }) {
    my $keyId = $sig->key_id_hex || next;
    next unless $keys{ $keyId };
    push(@out, $sig);
  }
  return @out;
}

sub self_sigs {
  my($kb, $key_id) = @_;
  my @out;
  foreach my $sig (@{ $kb->{'pkt'}->{'Crypt::OpenPGP::Signature'} }) {
    if($sig->key_id && $sig->key_id eq $key_id) {
      push(@out, $sig);
    }
  }
  return @out;
}



1;
__END__

=head1 NAME

Crypt::OpenPGP::KeyBlock - Key block object

=head1 SYNOPSIS

    use Crypt::OpenPGP::KeyBlock;

    my $packet = Crypt::OpenPGP::UserID->new( Identity => 'foo' );
    my $kb = Crypt::OpenPGP::KeyBlock->new;
    $kb->add($packet);

    my $serialized = $kb->save;

=head1 DESCRIPTION

I<Crypt::OpenPGP::KeyBlock> represents a single keyblock in a keyring.
A key block is essentially just a set of associated keys containing
exactly one master key, zero or more subkeys, some user ID packets, some
signatures, etc. The key is that there is only one master key
associated with each keyblock.

=head1 USAGE

=head2 Crypt::OpenPGP::KeyBlock->new

Constructs a new key block object and returns that object.

=head2 $kb->encrypting_key

Returns the key that performs encryption in this key block. For example,
if a DSA key is the master key in a key block with an ElGamal subkey,
I<encrypting_key> returns the ElGamal subkey certificate, because DSA
keys do not perform encryption/decryption.

=head2 $kb->signing_key

Returns the key that performs signing in this key block. For example,
if a DSA key is the master key in a key block with an ElGamal subkey,
I<encrypting_key> returns the DSA master key certificate, because DSA
supports signing/verification.

=head2 $kb->add($packet)

Adds the packet I<$packet> to the key block. If the packet is a PGP
certificate (a I<Crypt::OpenPGP::Certificate> object), the certificate
is also added to the internal key-management mechanism.

=head2 $kb->save

Serializes each of the packets contained in the I<KeyBlock> object,
in order, and returns the serialized data. This output can then be
fed to I<Crypt::OpenPGP::Armour> for ASCII-armouring, for example,
or can be written out to a keyring file.

=head2 $kb->save_armoured

Saves an armoured version of the keyblock (this is useful for exporting
public keys).

=head2 $kb->display

Returns a list of strings that can be shown to the user, describing
the contents of this keyblock.

=head2 $kb->all_user_ids

Returns a list of all user ids (as strings) that are defined in this
keyblock. This will be a list of all email addresses associated with
this key.

=head2 $kb->all_keys

Returns a list of L<Crypt::OpenPGP::Certificate> objects that are
defined within this keyblock. This will include a single master key,
and zero or more subkeys.

=head2 $kb->all_signatures

Returns a list of L<Crypt::OpenPGP::Signature> objects that are
defined within this keyblock. There will be at least one self
signature block (that is, signed by the master key) to associate the
master key with a user id. There may well be signature blocks to bind
the master key to the subkeys, and signature blocks from other users
certifying that this key is associated with this user id.

=head2 $kb->all_self_sigs

Returns a list of L<Crypt::OpenPGP::Signature> objects that are
defined within this keyblock, and signed by one of the keys in this
keyblock (as opposed to signatures signed by other users).

=head2 $kb->self_sigs($keyId)

Returns a list of L<Crypt::OpenPGP::Signature> objects that are signed
by the specified key id.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::OpenPGP manpage for author, copyright, and
license information.

=cut
