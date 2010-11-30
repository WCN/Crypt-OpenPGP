#! /usr/bin/perl

use strict;
use warnings;

use Test::More tests => 72;
use Data::Dumper;

use Crypt::OpenPGP;
use Crypt::OpenPGP::Message;

my $uid  = 'Bob Bobbage <bob@example.com>';
my $pass = "AllUrBase";
my $pgp  = Crypt::OpenPGP->new();
my $type = "RSA";      ## ElGamal key generation not supported yet...

diag("Keygen with subkey: '$type'");

my($pub, $sec) = $pgp->keygen(
  Type        => $type,
  Size        => 512,
  Passphrase  => $pass,
  Identity    => $uid,
  Subkey      => 1,
);

isa_ok($pub, "Crypt::OpenPGP::KeyBlock", "Got a public keyblock ok");
isa_ok($sec, "Crypt::OpenPGP::KeyBlock", "Got a secret keyblock ok");


ok(my $cert1 = $pub->key(), "Get main public cert");
isa_ok($cert1, "Crypt::OpenPGP::Certificate", "Got a certificate object");
ok(! $cert1->is_secret, "Not a secret key");
ok(! $cert1->is_subkey, "Not a subkey");
ok(! $cert1->is_protected, "Is not protected ok");
is($cert1->uid, $uid, "User id correct");
ok($cert1->can_encrypt, "Can be used for encryption");
ok($cert1->can_sign, "Can be used for signing");

ok(my $key1 = $cert1->key, "Get the actual key");
isa_ok($key1, "Crypt::OpenPGP::Key", "Got a key object");
isa_ok($key1, "Crypt::OpenPGP::Key::Public::${type}", "Got a $type key");
is($key1->alg, $type, "Has correct algorithm ($type)");
is($key1->size, 512, "Key size is ok");


ok(my $cert2 = $sec->key(), "Get main secret cert");
isa_ok($cert2, "Crypt::OpenPGP::Certificate", "Got a certificate object");
is($cert2->key_id_hex, $cert1->key_id_hex, "Have same key ids");
ok($cert2->is_secret, "Is a secret key");
ok(! $cert2->is_subkey, "Not a subkey");
ok($cert2->is_protected, "Is protected ok");
is($cert2->uid, $uid, "User id correct");
ok($cert2->can_encrypt, "Can be used for encryption");
ok($cert2->can_sign, "Can be used for signing");

ok(my $key2 = $cert2->key, "Get the actual key");
isa_ok($key2, "Crypt::OpenPGP::Key", "Got a key object");
isa_ok($key2, "Crypt::OpenPGP::Key::Secret::${type}", "Got a $type key");
is($key2->alg, $type, "Has correct algorithm ($type)");
is($key2->size, 512, "Key size is ok");


ok(my $cert3 = $pub->subkey(), "Get main public subcert");
isa_ok($cert3, "Crypt::OpenPGP::Certificate", "Got a certificate object");
isnt($cert3->key_id_hex, $cert1->key_id_hex, "Different key ids");
ok(! $cert3->is_secret, "Not a secret key");
ok($cert3->is_subkey, "Is a subkey");
ok(! $cert3->is_protected, "Is not protected ok");
is($cert3->uid, $uid, "User id correct");
ok($cert3->can_encrypt, "Can be used for encryption");
ok($cert3->can_sign, "Can be used for signing");

ok(my $key3 = $cert3->key, "Get the actual key");
isa_ok($key3, "Crypt::OpenPGP::Key", "Got a key object");
isa_ok($key3, "Crypt::OpenPGP::Key::Public::${type}",
       "Got a $type key");
is($key3->alg, $type, "Has correct algorithm ($type)");
is($key3->size, 512, "Key size is ok");


ok(my $cert4 = $sec->subkey(), "Get main secret subcert");
isa_ok($cert4, "Crypt::OpenPGP::Certificate", "Got a certificate object");
is($cert4->key_id_hex, $cert3->key_id_hex, "Have same key ids");
ok($cert4->is_secret, "Is a secret key");
ok($cert4->is_subkey, "Is a subkey");
ok($cert4->is_protected, "Is protected ok");
ok($cert4->can_encrypt, "Can be used for encryption");
ok($cert4->can_sign, "Can be used for signing");
is($cert4->uid, $uid, "User id correct");
ok($cert4->can_encrypt, "Can be used for encryption");
ok($cert4->can_sign, "Can be used for signing");

ok(my $key4 = $cert4->key, "Get the actual key");
isa_ok($key4, "Crypt::OpenPGP::Key", "Got a key object");
isa_ok($key4, "Crypt::OpenPGP::Key::Secret::${type}",
       "Got a $type key");
is($key4->alg, $type, "Has correct algorithm ($type)");
is($key4->size, 512, "Key size is ok");


ok(my @sigs = $pub->all_signatures, "List all signatures");
is(@sigs, 2, "Got 2 signatures");

is($sigs[0]->key_id_hex, $cert1->key_id_hex, "sig 0 key id ok");
is($sigs[0]->type, 0x13, "Sig type - link key with user id");
ok(time() - $sigs[0]->timestamp < 600, "Timestamp in last 600 secs");
is_deeply($sigs[0]->preferred_symmetric_algorithms, [ 9, 8, 7, 2 ],
          "Preferred symmetric algorithms ok");
is_deeply($sigs[0]->preferred_hash_algorithms, [ 2 ],
          "Preferred hash algorithms ok");
is_deeply($sigs[0]->preferred_compression_algorithms, [ 2, 3, 1 ],
          "Preferred compression algorithms ok");
is_deeply($sigs[0]->key_flags, {
  'can_certify_other_keys'     => 1,
  'can_sign_data'              => 1,
  'can_encrypt_communications' => 0,
  'can_encrypt_storage'        => 0,
  'private_key_may_be_split'   => 0,
  'can_use_authentication'     => 0,
  'private_key_multiple_users' => 0,
}, "Key flags ok");


is($sigs[1]->key_id_hex, $cert1->key_id_hex, "sig 0 key id ok");
is($sigs[1]->type, 0x18, "Sig type - signing of subkey");
ok(time() - $sigs[1]->timestamp < 600, "Timestamp in last 600 secs");
is_deeply($sigs[1]->key_flags, {
  'can_certify_other_keys'     => 0,
  'can_sign_data'              => 0,
  'can_encrypt_communications' => 1,
  'can_encrypt_storage'        => 1,
  'private_key_may_be_split'   => 0,
  'can_use_authentication'     => 0,
  'private_key_multiple_users' => 0,
}, "Key flags ok");


