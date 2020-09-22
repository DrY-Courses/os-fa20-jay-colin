# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(print-name) begin
(print-name) Linux RY
(print-name) end
EOF
pass;
