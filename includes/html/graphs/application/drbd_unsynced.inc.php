<?php

$scale_min = 0;

require 'includes/html/graphs/common.inc.php';

$rrd_filename = Rrd::name($device['hostname'], ['app', 'drbd', $app->app_instance]);

$ds = 'oos';

$colour_area = 'CDEB8B';
$colour_line = '006600';

$colour_area_max = 'FFEE99';

$graph_max = 1;
$multiplier = 8;

$unit_text = 'Bytes';

require 'includes/html/graphs/generic_simplex.inc.php';
