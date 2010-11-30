#! /usr/bin/perl

use strict;
use warnings;

use Test::More tests => 208;
use FindBin '$RealBin';
use Data::Dumper;

use Crypt::OpenPGP;
use Crypt::OpenPGP::Message;
use Crypt::OpenPGP::KeyRing;



## Test the lenny key...
{
  ok(my $keyring = Crypt::OpenPGP::KeyRing->new(
      Filename => "$RealBin/samples/keys/lenny.key",
  ), "Read the Debian Lenny public key");
  $keyring->read();

  is($keyring->keyblock_count, 1, "Contains one keyblock");

  ok(my $kb = $keyring->find_keyblock_by_index(0), "Get first keyblock");
  isa_ok($kb, "Crypt::OpenPGP::KeyBlock", "Got a keyblock ok");

  ok(my @keys = $kb->all_keys(), "List all keys");
  is(@keys, 1, "Got one key");
  is($keys[0]->version, 4, "Key version 4 ok");
  is($keys[0]->timestamp, 1207487218, "Key timestamp ok");
  is($keys[0]->pk_alg, 17, "pk_alg is DSA ok");
  is($keys[0]->is_secret, 0, "Not a secret key");
  is($keys[0]->is_subkey, 0, "Not a subkey");
  ok(! $keys[0]->is_protected, "Not protected");
  ok(! $keys[0]->can_encrypt, "Can't encrypt");
  is($keys[0]->can_sign, 1, "Can encrypt");

  ok(my @uids = $kb->all_user_ids(), "List all user ids");
  is(@uids, 1, "Got one user id");
  is($uids[0], 'Lenny Stable Release Key <debian-release@lists.debian.org>',
     "User id correct");

  ok(my @sigs = $kb->all_signatures(), "List all signatures");
  is(@sigs, 6, "Got 6 signatures");
  foreach my $sig (@sigs) {
    is($sig->uid, $uids[0], "Sig user id ok");
  }

  ok(my @selfsig = $kb->all_self_sigs(), "List all self signatures");
  is(@selfsig, 1, "Got one self signature");

  is($selfsig[0]->key_id_hex, "4D270D06F42584E6", "key id ok");
  is($selfsig[0]->timestamp, 1207487218, "signature timestamp ok");
  is($selfsig[0]->expiration_time, 129600000, "Expiration time ok");
  is($selfsig[0]->uid, $uids[0], "Self sig user id ok");
  ok(! $selfsig[0]->is_primary_user_id, "Not primary user id ok");
  is_deeply($selfsig[0]->preferred_symmetric_algorithms,
            [ 9, 8, 7, 3, 2 ],
            "Preferred algorithms (AES 256, 192, 128), CAST5, 3DES)");
  is_deeply($selfsig[0]->preferred_hash_algorithms,
            [ 2, 8, 3 ],
            "Preferred hashes (SHA1, SHA256, RIMPEMD160)");
  is_deeply($selfsig[0]->preferred_compression_algorithms,
            [ 2, 3, 1 ],
            "Preferred compression (ZLIB, BZIP2, ZIP)");
  is_deeply($selfsig[0]->key_flags, {
    'can_certify_other_keys'     => 1,
    'can_sign_data'              => 1,
    'can_encrypt_communications' => 0,
    'can_encrypt_storage'        => 0,
    'private_key_may_be_split'   => 0,
    'can_use_authentication'     => 0,
    'private_key_multiple_users' => 0,
  }, "Key flags ok");


  ok(my @keysigs = $keys[0]->self_signatures, "Get key self signatures");
  is(@keysigs, 1, "Got one key signature");
  is($keysigs[0], $selfsig[0], "Got the only self signature");

}






## Test the squeeze key......
##
{
  ok(my $keyring = Crypt::OpenPGP::KeyRing->new(
      Filename => "$RealBin/samples/keys/squeeze.key",
  ), "Read the Debian Squeeze public key");
  $keyring->read();

  is($keyring->keyblock_count, 1, "Contains one keyblock");

  ok(my $kb = $keyring->find_keyblock_by_index(0), "Get first keyblock");
  isa_ok($kb, "Crypt::OpenPGP::KeyBlock", "Got a keyblock ok");

  ok(my @keys = $kb->all_keys(), "List all keys");
  is(@keys, 1, "Got one key");
  is($keys[0]->version, 4, "Key version 4 ok");
  is($keys[0]->timestamp, 1282940623, "Key timestamp ok");
  is($keys[0]->pk_alg, 1, "pk_alg is RSA ok");
  is($keys[0]->is_secret, 0, "Not a secret key");
  is($keys[0]->is_subkey, 0, "Not a subkey");
  ok(! $keys[0]->is_protected, "Not protected");
  ok($keys[0]->can_encrypt, "Can encrypt");
  is($keys[0]->can_sign, 1, "Can encrypt");


  ok(my @uids = $kb->all_user_ids(), "List all user ids");
  is(@uids, 1, "Got one user id");
  is($uids[0],
     'Debian Archive Automatic Signing Key (6.0/squeeze) <ftpmaster@debian.org>',
     "User id correct");

  ok(my @sigs = $kb->all_signatures(), "List all signatures");
  is(@sigs, 9, "Got 9 signatures");
  foreach my $sig (@sigs) {
    is($sig->uid, $uids[0], "Sig user id ok");
  }

  ok(my @selfsig = $kb->all_self_sigs(), "List all self signatures");
  is(@selfsig, 1, "Got one self signature");


  is($selfsig[0]->key_id_hex, "AED4B06F473041FA", "key id ok");
  is($selfsig[0]->timestamp, 1282940896, "signature timestamp ok");
  is($selfsig[0]->expiration_time, 237340800, "Expiration time ok");
  is($selfsig[0]->uid, $uids[0], "Self sig user id ok");
  ok(! $selfsig[0]->is_primary_user_id, "Not primary user id ok");
  is_deeply($selfsig[0]->preferred_symmetric_algorithms,
            [ 9, 8, 7, 3, ],
            "Preferred algorithms (AES 256, 192, 128), CAST5)");
  is_deeply($selfsig[0]->preferred_hash_algorithms,
            [ 8, 9, 10, 11 ],
            "Preferred hashes (SHA 256, 384, 512, 224)");
  is_deeply($selfsig[0]->preferred_compression_algorithms,
            [ 2, 3, 1, 0 ],
            "Preferred compression (ZLIB, BZIP2, ZIP, none)");
  is_deeply($selfsig[0]->key_flags, {
    'can_certify_other_keys'     => 1,
    'can_sign_data'              => 1,
    'can_encrypt_communications' => 0,
    'can_encrypt_storage'        => 0,
    'private_key_may_be_split'   => 0,
    'can_use_authentication'     => 0,
    'private_key_multiple_users' => 0,
  }, "Key flags ok");


  ok(my @keysigs = $keys[0]->self_signatures, "Get key self signatures");
  is(@keysigs, 1, "Got one key signature");
  is($keysigs[0], $selfsig[0], "Got the only self signature");

}






## Test the EFF key......
##
{
  ok(my $keyring = Crypt::OpenPGP::KeyRing->new(
      Filename => "$RealBin/samples/keys/eff.key",
  ), "Read the Debian Squeeze public key");
  $keyring->read();

  is($keyring->keyblock_count, 1, "Contains one keyblock");

  ok(my $kb = $keyring->find_keyblock_by_index(0), "Get first keyblock");
  isa_ok($kb, "Crypt::OpenPGP::KeyBlock", "Got a keyblock ok");

  ok(my @keys = $kb->all_keys(), "List all keys");
  is(@keys, 1, "Got one key");
  is($keys[0]->key_id_hex, "9DB5FFEE99592FED", "key id ok");
  is($keys[0]->version, 3, "Key version 3 ok");
  is($keys[0]->timestamp, 785421532, "Key timestamp ok");
  is($keys[0]->validity, 0, "Key validity ok");
  is($keys[0]->pk_alg, 1, "pk_alg is RSA ok");
  is($keys[0]->is_secret, 0, "Not a secret key");
  is($keys[0]->is_subkey, 0, "Not a subkey");
  ok(! $keys[0]->is_protected, "Not protected");
  ok($keys[0]->can_encrypt, "Can encrypt");
  is($keys[0]->can_sign, 1, "Can encrypt");


  ok(my @uids = $kb->all_user_ids(), "List all user ids");
  is(@uids, 9, "Got nine user ids");
  is($uids[0], 'EFF <181:193/1@StormNet>', 'User id 0 ok');
  is($uids[1], 'EFF <1:109/1108@FidoNet>', 'User id 1 ok');
  is($uids[2], 'EFF <19:1202/101@WishNet>', 'User id 2 ok');
  is($uids[3], 'EFF <369:1011/2@IndraNet>', 'User id 3 ok');
  is($uids[4], 'EFF <76711.317@compuserve.com>', 'User id 4 ok');
  is($uids[5], 'Discard older key - it\'s revoked', 'User id 5 ok');
  is($uids[6], 'EFF <eff@well.com, eff@well.sf.ca.us>', 'User id 6 ok');
  is($uids[7],
     'Electronic Frontier Foundation <eff@eff.org>',
     'User id 7 ok');
  is($uids[8],
     'Electronic Frontier Foundation (EFF) membership coordinator '.
       '<membership@eff.org>',
     'User id 8 ok');

  ok(my @sigs = $kb->all_signatures(), "List all signatures");
  is(@sigs, 70, "Got 70 signatures");

  ok(my @selfsig = $kb->all_self_sigs(), "List all self signatures");
  is(@selfsig, 7, "Got seven self signature");

  foreach my $selfsig (@selfsig) {
    is($selfsig->key_id_hex, "9DB5FFEE99592FED", "signature key id ok");
  }

  is($selfsig[0]->uid, $uids[5], "SelfSig 0 user id");
  is($selfsig[1]->uid, $uids[6], "SelfSig 1 user id");
  is($selfsig[2]->uid, $uids[7], "SelfSig 2 user id");
  is($selfsig[3]->uid, $uids[7], "SelfSig 3 user id");
  is($selfsig[4]->uid, $uids[7], "SelfSig 4 user id");
  is($selfsig[5]->uid, $uids[8], "SelfSig 5 user id");
  is($selfsig[6]->uid, $uids[8], "SelfSig 6 user id");

  is($selfsig[0]->version, 3, "SelfSig 0 version");
  is($selfsig[1]->version, 3, "SelfSig 1 version");
  is($selfsig[2]->version, 3, "SelfSig 2 version");
  is($selfsig[3]->version, 4, "SelfSig 3 version");
  is($selfsig[4]->version, 4, "SelfSig 4 version");
  is($selfsig[5]->version, 4, "SelfSig 5 version");
  is($selfsig[6]->version, 4, "SelfSig 6 version");

  is($selfsig[0]->timestamp, 842658090, "SelfSig 0 timestamp");
  is($selfsig[1]->timestamp, 1033354710, "SelfSig 1 timestamp");
  is($selfsig[2]->timestamp, 785421670, "SelfSig 2 timestamp");
  is($selfsig[3]->timestamp, 1025213089, "SelfSig 3 timestamp");
  is($selfsig[4]->timestamp, 1025213089, "SelfSig 4 timestamp");
  is($selfsig[5]->timestamp, 1033354777, "SelfSig 5 timestamp");
  is($selfsig[6]->timestamp, 1033354777, "SelfSig 6 timestamp");

  ok(! $selfsig[3]->find_subpacket(101), "SelfSig 3 has NO reserved subpacket");
  ok($selfsig[4]->find_subpacket(101), "SelfSig 4 has reserved subpacket");
  ok(! $selfsig[5]->find_subpacket(101), "SelfSig 5 has NO reserved subpacket");
  ok($selfsig[6]->find_subpacket(101), "SelfSig 6 has reserved subpacket");

  ok(! $selfsig[0]->is_primary_user_id, "SelfSig 0 is NOT primary uid");
  ok(! $selfsig[1]->is_primary_user_id, "SelfSig 1 is NOT primary uid");
  ok(! $selfsig[2]->is_primary_user_id, "SelfSig 2 is NOT primary uid");
  ok($selfsig[3]->is_primary_user_id, "SelfSig 3 is primary uid");
  ok($selfsig[4]->is_primary_user_id, "SelfSig 4 is primary uid");
  ok($selfsig[5]->is_primary_user_id, "SelfSig 5 is primary uid");
  ok($selfsig[6]->is_primary_user_id, "SelfSig 6 is primary uid");


  is($kb->primary_uid, $uids[8], "Primary UID uses timestamp resolution");
}




## Test the bobbage key...
{
  ok(my $keyring = Crypt::OpenPGP::KeyRing->new(
      Filename => "$RealBin/samples/keys/bobbage.key",
  ), "Read the bobbage key");
  $keyring->read();

  is($keyring->keyblock_count, 1, "Contains one keyblock");

  ok(my $kb = $keyring->find_keyblock_by_index(0), "Get first keyblock");
  isa_ok($kb, "Crypt::OpenPGP::KeyBlock", "Got a keyblock ok");

  ok(my @keys = $kb->all_keys(), "List all keys");
  is(@keys, 2, "Got two keys");

  is($keys[0]->key_id_hex, "BBE007BAC5D9F434", "key id ok");
  is($keys[0]->version, 4, "Key version 4 ok");
  is($keys[0]->timestamp, 1291078716, "Key timestamp ok");
  is($keys[0]->pk_alg, 1, "pk_alg is RSA ok");
  is($keys[0]->is_secret, 0, "Not a secret key");
  is($keys[0]->is_subkey, 0, "Not a subkey");
  ok(! $keys[0]->is_protected, "Not protected");
  ok($keys[0]->can_encrypt, "Can encrypt");
  is($keys[0]->can_sign, 1, "Can sign");
  is($keys[0]->key->size, 2048, "Key size ok");
  is($keys[0]->key->alg, "RSA", "Key algorithm, ok");

  is($keys[1]->key_id_hex, "43CAE5B6F0D06794", "key id ok");
  is($keys[1]->version, 4, "Key version 4 ok");
  is($keys[1]->timestamp, 1291078716, "Key timestamp ok");
  is($keys[1]->pk_alg, 1, "pk_alg is RSA ok");
  is($keys[1]->is_secret, 0, "Not a secret key");
  is($keys[1]->is_subkey, 1, "IS a subkey");
  ok(! $keys[1]->is_protected, "Not protected");
  ok($keys[1]->can_encrypt, "Can encrypt");
  is($keys[1]->can_sign, 1, "Can sign");
  is($keys[1]->key->size, 2048, "Key size ok");
  is($keys[1]->key->alg, "RSA", "Key algorithm, ok");


  ok(my @uids = $kb->all_user_ids(), "List all user ids");
  is(@uids, 1, "Got one user id");
  is($uids[0], 'Bob Bobbage (Mmmmm, Pie) <bob123@example.com>',
     "User id correct");

  ok(my @sigs = $kb->all_signatures(), "List all signatures");
  is(@sigs, 2, "Got 2 signatures");
  foreach my $sig (@sigs) {
    is($sig->uid, $uids[0], "Sig user id ok");
  }


  ok(my @selfsig = $kb->all_self_sigs(), "List all self signatures");
  is(@selfsig, 2, "Got two self signatures");

  is($selfsig[0]->key_id_hex, "BBE007BAC5D9F434", "key id ok");
  is($selfsig[0]->type, 0x13, "Sig type - link key with user id");
  is($selfsig[0]->timestamp, 1291078716, "signature timestamp ok");
  is($selfsig[0]->expiration_time, 31536000, "Expiration time ok");
  is($selfsig[0]->uid, $uids[0], "Self sig user id ok");
  ok(! $selfsig[0]->is_primary_user_id, "Not primary user id ok");
  is_deeply($selfsig[0]->preferred_symmetric_algorithms,
            [ 9, 8, 7, 3, 2 ],
            "Preferred algorithms (AES 256, 192, 128), CAST5, 3DES)");
  is_deeply($selfsig[0]->preferred_hash_algorithms,
            [ 8, 2, 9, 10, 11 ],
            "Preferred hashes (SHA (256, 1, 384, 512, 224)");
  is_deeply($selfsig[0]->preferred_compression_algorithms,
            [ 2, 3, 1 ],
            "Preferred compression (ZLIB, BZIP2, ZIP)");
  is_deeply($selfsig[0]->key_flags, {
    'can_certify_other_keys'     => 1,
    'can_sign_data'              => 1,
    'can_encrypt_communications' => 0,
    'can_encrypt_storage'        => 0,
    'private_key_may_be_split'   => 0,
    'can_use_authentication'     => 0,
    'private_key_multiple_users' => 0,
  }, "Key flags ok");


  is($selfsig[1]->key_id_hex, "BBE007BAC5D9F434", "key id ok");
  is($selfsig[1]->type, 0x18, "Sig type - subkey signing");
  is($selfsig[1]->timestamp, 1291078716, "signature timestamp ok");
  is($selfsig[1]->expiration_time, 31536000, "Expiration time ok");
  is($selfsig[1]->uid, $uids[0], "Self sig user id ok");
  ok(! $selfsig[1]->is_primary_user_id, "Not primary user id ok");
  is_deeply($selfsig[1]->key_flags, {
    'can_certify_other_keys'     => 0,
    'can_sign_data'              => 0,
    'can_encrypt_communications' => 1,
    'can_encrypt_storage'        => 1,
    'private_key_may_be_split'   => 0,
    'can_use_authentication'     => 0,
    'private_key_multiple_users' => 0,
  }, "Key flags ok");




  is($kb->signing_key->key_id_hex, "BBE007BAC5D9F434",
     "master key used for signin");
  is($kb->encrypting_key->key_id_hex, "43CAE5B6F0D06794",
     "sub key used for encryption");


}






