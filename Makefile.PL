use utf8;
use inc::Module::Install;

perl_version '5.009005';

name 're-engine-PCRE';
author 'Ævar Arnfjörð Bjarmason <avar@cpan.org>'; 

abstract_from 'PCRE.pm';
license_from 'PCRE.pm';
version_from 'PCRE.pm';

# t/
build_requires 'Config'     => 0;
build_requires 'XSLoader'   => 0;
build_requires 'Test::More' => 0; # 5.007003

makemaker_args DIR => [ 'libpcre' ];
makemaker_args INC => '-Ilibpcre';
makemaker_args LDDLFLAGS => '-shared libpcre/*.o';

tests 't/*.t t/*/*.t';

auto_install;
WriteAll;
