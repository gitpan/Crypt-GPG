# -*-cperl-*-
#
# gpg.t - Test Crypt::GPG module.
# Copyright (c) 2001 Ashish Gulhati <hash@netropolis.org>
#
# All rights reserved. This code is free software; you can
# redistribute it and/or modify it under the same terms as Perl
# itself.
#
# $Id: gpg.t,v 1.4 2001/11/10 15:50:15 cvs Exp $

use strict;
use Test;
use Crypt::GPG;

BEGIN { plan tests => 52 }

my $pgpcompat = 0; # Set to 1 to test PGP5 compatibility.

my ($gpg, $pgp, @x, @y, $pub, $sec);
my ($gpgdebug, $pgpdebug) = (0,0);
my $dir = $0 =~ /^\// ? $0 : $ENV{PWD} . '/' . $0; $dir =~ s/\/[^\/]*$//;
$ENV{HOME} = $dir;

print "Warning: These tests can take quite a while...\n\n";

ok(sub {
     $gpg = new Crypt::GPG;
   });

ok(sub {
     eval { if ($pgpcompat) {
              use Crypt::PGP5;
	      $pgp = new Crypt::PGP5;
	    }
	    $pgp or print "Warning: Skipping PGP 5 compatibility tests.\n";
	  };
     return 1;
   });

ok(sub {
     $gpg->gpgopts('--compress-algo 1 --cipher-algo cast5 --force-v3-sigs --no-comment');
     $gpg->debug($gpgdebug);
   }, $gpgdebug);

skip(!$pgp, sub {
       $pgp->delay(0.1);
       $pgp->debug($pgpdebug);
     }, $pgpdebug);

for my $bits (768, 1024, 2048, 4096) {
  for my $type ('ELG-E') {

    # Generate key pair

    ok(sub {
	 my $status = $gpg->keygen("A $bits $type", "$bits$type\@test.com", 
				   $type, $bits, 0, "$bits Bit $type Test Key");
	 return 0 unless $status;
	 $|=1;
	 while (<$status>) {
	   chomp; print;
	 }
	 close $status; print "\n"; $|=0;
       }, 0);

    # Export public key

    ok(sub {
	 my ($key) = grep { $_->{Type} =~ /^pub[^\@]?/ } $gpg->keyinfo("A $bits $type");
	 $pub = $gpg->export($key);
       });

    # Export secret key

    ok(sub {
	 my ($key) = grep { $_->{Type} =~ /^sec[^\@]?/ } $gpg->keyinfo("A $bits $type");
	 $sec = $gpg->export($key);
       });

    # Import public key into PGP

    skip(!$pgp, sub {
	   $pgp->addkey($pub);
	 });

    # Import secret key into PGP5

    skip(!$pgp, sub {
	   $pgp->addkey($sec);
	 });

    # Encrypt with GPG
    
    ok(sub {
       @x = $gpg->encrypt("Test\n", "A $bits $type");
     });

    # If possible, also with PGP5
    
    skip(!$pgp, sub {
	   $pgp->encryptsafe(0);
	   @y = $pgp->encrypt(["A $bits $type"], 'Test');
	 });
    
    # Decrypt GPG with GPG
    
    ok(sub {
	 $gpg->passphrase("$bits Bit $type Test Key");
	 my ($clear) = $gpg->decrypt(@x);
	 $clear eq "Test\n";
       });
    
    # Decrypt PGP with GPG
    
    skip(!$pgp, sub {
	   my ($clear) = $gpg->decrypt(@y);
	   $clear eq "Test\n";
	 });
    
    # Decrypt GPG with PGP
    
    skip(!$pgp, sub {
	   $pgp->passphrase("$bits Bit $type Test Key");
	   my (undef, $clear) = $pgp->decrypt(@x);
	   $clear eq "Test\n";
	 });
    
    # Decrypt PGP with PGP
    
    skip(!$pgp, sub {
	   my (undef, $clear) = $pgp->decrypt(@y);
	   $clear eq "Test\n";
	 });
    
    # Delete GPG key pair

    ok(sub {
	 my ($key) = grep { $_->{Type} =~ /^sec[^\@]?/ } $gpg->keyinfo("A $bits $type");
	 $gpg->delkey($key);
       });
  }
}
