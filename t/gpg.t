# -*-cperl-*-
#
# gpg.t - Test Crypt::GPG module.
# Copyright (c) 2001-2002 Ashish Gulhati <hash@netropolis.org>
#
# All rights reserved. This code is free software; you can
# redistribute it and/or modify it under the same terms as Perl
# itself.
#
# $Id: gpg.t,v 1.13 2002/09/22 09:22:38 cvs Exp $

use strict;
use Test;
use Crypt::GPG;

BEGIN { plan tests => 58 }

my $pgpcompat = 0; # Set to 1 to test PGP5 compatibility.

print STDERR "\n\n*** NOTE: Some of these tests can take quite a long time. ***\n";

my ($gpg, $pgp, @x, @y, $pub, $sec);
my ($gpgdebug, $pgpdebug) = (0,0);
my $dir = $0 =~ /^\// ? $0 : $ENV{PWD} . '/' . $0; $dir =~ s/\/[^\/]*$//;
$ENV{HOME} = $dir;
my @samplekeys; samplekeys();


#1
ok(sub {
     if ($pgpcompat) {
       eval { 
	 require Crypt::PGP5;
	 $pgp = new Crypt::PGP5;
       };
     }
     $pgp or print STDERR "*** Skipping PGP5 compatibility tests. ***\n";
     print STDERR "\n";
   });

#2
ok(sub {
     $gpg = new Crypt::GPG;
#     $gpg->delay(0.2);
   });

#3
ok(sub {
     $gpg->gpgopts('--compress-algo 1 --cipher-algo cast5 --force-v3-sigs --no-comment');
     $gpg->debug($gpgdebug);
   }, $gpgdebug);

#4
skip(!$pgp, sub {
       #$pgp->delay(0.1);
       $pgp->debug($pgpdebug);
     }, $pgpdebug);

for my $bits (768) {
  for my $type ('ELG-E') {

    #5 Generate key pair

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

    #6 Import some sample keys into GPG

    ok(sub {
	 for my $x (@samplekeys) {
	   my ($imported) = $gpg->addkey($x->{Key});
	   return 0 unless $imported->{ID} eq $x->{ID};
	 }
	 1;
       });
    
    #7 Export our public key

    my $publickey;

    ok(sub {
	 ($publickey) = grep { $_->{Type} =~ /^pub[^\@]?/ } $gpg->keyinfo("A $bits $type");
	 $pub = $gpg->export($publickey);
       });

    #8 Import public key into PGP

    skip(!$pgp, sub {
	   $pgp->addkey($pub);
	 });

    #9 Pretend import public key into GPG

    ok(sub {
	 my ($imported) = $gpg->addkey($pub, 1);
	 $publickey->{ID} eq $imported->{ID};
       });

    #10 Really import public key into GPG

    ok(sub {
	 my ($imported) = $gpg->addkey($pub);
	 $publickey->{ID} eq $imported->{ID};
       });

    #11 Export GPG secret key
      
    my $secretkey;

    ok(sub {
	 ($secretkey) = grep { $_->{Type} =~ /^sec[^\@]?/ } $gpg->keyinfo("A $bits $type");
	 $sec = $gpg->export($secretkey);
       });
      
    #12 Import secret key into PGP5
    
    skip(!$pgp, sub {
	   $pgp->addkey($sec);
	 });
    
    #13 Encrypt with GPG
      
    ok(sub {
	 @x = $gpg->encrypt("Test\n", "A $bits $type");
       });
    
    #14 If possible, also with PGP5
      
    skip(!$pgp, sub {
	   $pgp->encryptsafe(0);
	   @y = $pgp->encrypt(["A $bits $type"], 'Test');
	 });
      
    $gpg->passphrase("$bits Bit $type Test Key");
    $gpg->secretkey($secretkey->{ID});

    for my $nopass (0..1) {

      if ($nopass) {
	#35 Blank out the Key password and do another round of tests.

	ok(sub {
	     $gpg->passphrase('');
	     $gpg->keypass($secretkey, "Bitty $bits $type Test Key", '');
	   });
      }
      
      #15 Local-sign all sample public keys
      #! Test check for already signed.
      #! Test check for UID out of range. It's broken.
      
      ok(sub {
	   for my $x (@samplekeys) {
	     return unless $gpg->certify($x->{ID}, 1, 0);
	   }
	   1;
	 });

      #16 Sign all sample public keys
      
      ok(sub {
	   for my $x (@samplekeys) {
	     return unless $gpg->certify($x->{ID}, 0, 0);
	   }
	   1;
	 });

      #17 Verify key signatures with PGP

      skip(!$pgp, sub {});

##      #18 Verify key signatures with GPG

      ok(sub {1});

      #19 Encrypt and sign with GPG

      my @xs;
      ok(sub {
	   @xs = $gpg->encrypt("Test\n", "A $bits $type", '-sign');
	 });

      #20 Sign with GPG
      #! Need to check for hang when secret key not set.

      ok(sub {
	   my $signed = $gpg->sign("Signing a test\nmessage, combining\nand\r\nline endings.\n");
	   print $signed;
	 });

##      #21 Clearsign with GPG

      ok(sub {1});
      
##      #22 Detached sign with GPG

      ok(sub {1});

      #23 Decrypt GPG with GPG

      ok(sub {
	   $gpg->passphrase("$bits Bit $type Test Key");
	   my ($clear) = $gpg->decrypt(@x);
	   $clear eq "Test\n";
	 });

      #24 Decrypt & Verify GPG with GPG

      ok(sub {
	   $gpg->passphrase("$bits Bit $type Test Key");
	   my ($clear, $sign) = $gpg->decrypt(@xs);
	   $clear eq "Test\n" 
	     and ref($sign) eq 'Crypt::GPG::Signature';
	 });

##      #25 Verify Signature (GPG with GPG)

      ok(sub {1});

##      #26 Verify detached signature (GPG with GPG)

      ok(sub {1});
      
#      #27 Decrypt PGP with GPG
      
      skip(!$pgp, sub {
	     my ($clear) = $gpg->decrypt(@y);
	     $clear eq "Test\n";
	   });
    
#      #28 Decrypt & Verify PGP with GPG

      skip(!$pgp, sub {});

#      #29 Verify Signature (PGP with GPG)
 
      skip(!$pgp, sub {});

#      #30 Verify detached signature (PGP with GPG)
      
      skip(!$pgp, sub {});

      #31 Decrypt GPG with PGP
      
      skip(!$pgp, sub {
	     $pgp->passphrase("$bits Bit $type Test Key");
	     my (undef, $clear) = $pgp->decrypt(@x);
	     $clear eq "Test\n";
	   });
      
      #32 Decrypt & Verify GPG with PGP

      skip(!$pgp, sub {});

      #33 Verify Signature (GPG with PGP)
 
      skip(!$pgp, sub {});

      #34 Verify detached signature (GPG with PGP)
      
      skip(!$pgp, sub {});

      #35 Change password for key
      
      ok(sub {
	   $gpg->keypass($secretkey, $nopass ? '' : "$bits Bit $type Test Key", 
			 "Bitty $bits $type Test Key");
	 });
    }
    
    #58 Delete GPG key pair

    ok(sub {
	 $gpg->delkey($secretkey);
       });
  }
}

sub samplekeys {
  push (@samplekeys, {'ID' => 'D354E162BCA6DBD1',
		      'Key' => <<__ENDKEY
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.0.6 (GNU/Linux)
Comment: For info see http://www.gnupg.org

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
=wE/r
-----END PGP PUBLIC KEY BLOCK-----
__ENDKEY
		     });
}
