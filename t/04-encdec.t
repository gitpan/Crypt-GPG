# -*-cperl-*-
#
# enc-dec.t - Crypt::GPG encryption / decryption tests.
# Copyright (c) 2005 Ashish Gulhati <crypt-gpg@neomailbox.com>
#
# All rights reserved. This code is free software; you can
# redistribute it and/or modify it under the same terms as Perl
# itself.
#
# $Id: 04-encdec.t,v 1.4 2005/02/10 10:51:43 cvs Exp $

use strict;
use Test;
use Crypt::GPG;

BEGIN { plan tests => 15 }

my $debug = 0;
my $dir = $0 =~ /^\// ? $0 : $ENV{PWD} . '/' . $0; $dir =~ s/\/[^\/]*$//;
$ENV{HOME} = $dir;

# Create new Crypt::GPG object

my @x;
my $gpg = new Crypt::GPG;
$gpg->delay(0.1);
$gpg->gpgopts('--compress-algo 1 --cipher-algo cast5 --force-v3-sigs --no-comment');
$gpg->debug($debug);

# Start test loop with different key sizes/types
################################################
for my $bits qw(768 1024 2048) {
  for my $type ('ELG-E') {

    my ($secretkey) = grep { $_->{Type} =~ /^sec[^\@]?/ } $gpg->keyinfo("A $bits $type");
    $gpg->secretkey($secretkey);
    $gpg->encryptsafe(0);

    # Encrypt
    #########
    ok(sub {
	 @x = $gpg->encrypt("Test\n", "A $bits $type");
       });

    for my $nopass (0,1) {
      if ($nopass) {
	# Blank out the Key password and do another round of tests
        ##########################################################
	ok(sub {
	     $gpg->passphrase('');
	     $gpg->keypass($secretkey, "$bits Bit $type Test Key", '');
	   });
      }
      
      # Decrypt
      #########
      ok(sub {
	   $gpg->passphrase("$bits Bit $type Test Key") unless $nopass;
	   my ($clear) = $gpg->decrypt(@x);
	   $clear eq "Test\n";
	 });
    }

    # Set passphrase back to original
    #################################
    ok(sub {
	 $gpg->keypass($secretkey, '', "$bits Bit $type Test Key");
       });
  }
}


