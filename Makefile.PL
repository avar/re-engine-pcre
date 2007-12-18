use 5.009005;
use utf8;
use strict;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME		 => 're::engine::PCRE',
    AUTHOR       => 'Ævar Arnfjörð Bjarmason <avar@cpan.org>',
    VERSION_FROM => 'PCRE.pm',
    LIBS         => [ '-lpcre' ],
);
