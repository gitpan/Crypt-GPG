use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile (
	       'NAME'	      =>   'Crypt::GPG',
	       'AUTHOR'        =>  'Ashish Gulhati <hash@netropolis.org>',
	       'ABSTRACT_FROM' =>  'GPG.pm',
	       'VERSION_FROM'  =>  'GPG.pm',
	       'PREREQ_PM'     =>  {
				    'Carp'         =>  0,
				    'Fcntl'        =>  0,
				    'Expect'       =>  '1.15',
				    'File::Path'   =>  0,
				    'File::Temp'   =>  0,
				    'Date::Parse'  =>  0,
				    'Time::HiRes'  =>  0,
				   },
	      );

