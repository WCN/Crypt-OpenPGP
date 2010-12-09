#! /usr/bin/perl

use strict;
use warnings;

use Test::More tests => 34;
use FindBin '$RealBin';
use Data::Dumper;

use Crypt::OpenPGP;
use Crypt::OpenPGP::Message;
use Crypt::OpenPGP::KeyRing;

my $pass1 = "234567";
my $pass2 = "123456";

ok(my $pubring1 = Crypt::OpenPGP::KeyRing->new(
  Files => [ "$RealBin/samples/keys/billage.key",
             "$RealBin/samples/keys/bobbage.key" ],
), "Create a new public key ring object");

ok(my $secring1 = Crypt::OpenPGP::KeyRing->new(
  Files => [ "$RealBin/samples/keys/billage.sec" ],
), "Create a new secret key ring object");


ok(my $pubring2 = Crypt::OpenPGP::KeyRing->new(
  Files => [ "$RealBin/samples/keys/bobbage.key",
             "$RealBin/samples/keys/billage.key" ],
), "Create a new public key ring object");

ok(my $secring2 = Crypt::OpenPGP::KeyRing->new(
  Files => [ "$RealBin/samples/keys/bobbage.sec" ],
), "Create a new secret key ring object");


ok(my $kb1 = $pubring1->find_keyblock_by_index(0), "Get Bobbage Keyblock");
ok(my $kb2 = $pubring2->find_keyblock_by_index(0), "Get Billage Keyblock");


ok(my $pgp1 = Crypt::OpenPGP->new(
  PubRing => $pubring1,
  SecRing => $secring1,
), "Create a new OpenPGP object for Billage");

ok(my $pgp2 = Crypt::OpenPGP->new(
  PubRing => $pubring2,
  SecRing => $secring2,
), "Create a new OpenPGP object for Bobbage");




my $txt = <<"";
This is a test message.
Hello World.
I like buffy, beer, ponies and pies.


ok(my $enc = $pgp1->encrypt(
  SignKeyID        => $kb1->signing_key->key_id,
  SignPassphrase   => $pass1,
  Recipients       => 'Bob Bobbage',
  Digest           => 'SHA1',
  Compress         => 'Zlib',
  Cipher           => 'Rijndael',
  MDC              => 1,
  Armour           => 1,
  Data             => $txt,
), "Encrypt and sign our message") || die $pgp1->errstr;


ok(my $msg = Crypt::OpenPGP::Message->new( Data => $enc ),
   "Read the message we just generated");

is(@{ $msg->{pieces} }, 2, "Message has 2 pieces");

ok(my $sk = $msg->{pieces}->[0], "Get first piece");
isa_ok($sk, "Crypt::OpenPGP::SessionKey", "Got a session key");
is($sk->key_id_hex, "43CAE5B6F0D06794",
   "Key id is Bobbage's encrypting sub key");

isa_ok($msg->{pieces}->[1], "Crypt::OpenPGP::Ciphertext",
       "Got some ciphertext in the second piece");



ok(my($data, $valid, $sig) = $pgp2->decrypt(
  Data        => $enc,
  Passphrase  => $pass2,
), "Decrypt and validate signature");

is($data, $txt, "Data has been decrypted successfully");
is($valid, 'Bill Billage <bill@example.com>', 'Signature valid ok');

isa_ok($sig, "Crypt::OpenPGP::Signature", "Signature present ok");
is($sig->key_id_hex, "4459B35D6BB0BE15",
   "Signature made by Billage's signing key");
ok(time() - $sig->timestamp < 600, "Signature within last 10 mins");







## Now encrypt a second message, this time from Bobbage to Billage
##
$txt = <<"";
WTF man? Are you out of your mind?!?!?!

ok($enc = $pgp2->encrypt(
  SignKeyID        => $kb2->signing_key->key_id,
  SignPassphrase   => $pass2,
  Recipients       => 'Bill Billage',
  Digest           => 'SHA1',
  Compress         => 'Zlib',
  Cipher           => 'Rijndael',
  MDC              => 1,
  Armour           => 1,
  Data             => $txt,
), "Encrypt and sign our message") || die $pgp1->errstr;


ok($msg = Crypt::OpenPGP::Message->new( Data => $enc ),
   "Read the message we just generated");

is(@{ $msg->{pieces} }, 2, "Message has 2 pieces");

ok($sk = $msg->{pieces}->[0], "Get first piece");
isa_ok($sk, "Crypt::OpenPGP::SessionKey", "Got a session key");
is($sk->key_id_hex, "54E12CC820CAEB32",
   "Key id is Billage's encrypting sub key");

isa_ok($msg->{pieces}->[1], "Crypt::OpenPGP::Ciphertext",
       "Got some ciphertext in the second piece");


ok(($data, $valid, $sig) = $pgp1->decrypt(
  Data        => $enc,
  Passphrase  => $pass1,
), "Decrypt and validate signature");

is($data, $txt, "Data has been decrypted successfully");
is($valid, 'Bob Bobbage (Mmmmm, Pie) <bob123@example.com>',
   'Signature valid ok');

isa_ok($sig, "Crypt::OpenPGP::Signature", "Signature present ok");
is($sig->key_id_hex, "BBE007BAC5D9F434",
   "Signature made by Billage's signing key");
ok(time() - $sig->timestamp < 600, "Signature within last 10 mins");





