<?php

$link_array = [
    'page' => 'device',
    'device' => $device['device_id'],
    'tab' => 'apps',
    'app' => 'nfdump',
];

print_optionbar_start();

echo generate_link('Exporters', $link_array);
echo ' | ';
$sources = $app->data['exporters'] ?? [];
sort($sources);
foreach ($sources as $index => $source) {
    $source = htmlspecialchars($source);
    $label = $vars['exporter'] == $source
        ? '<span class="pagemenu-selected">' . $source . '</span>'
        : $source;

    echo generate_link($label, $link_array, ['exporter' => $source]);

    if ($index < (count($sources) - 1)) {
        echo ', ';
    }
}

print_optionbar_end();

if (! isset($vars['exporter'])) {
    if (isset($vars['exporter'])) {
        $vars['exporter'] = htmlspecialchars($vars['exporter']);
    }
    $graphs = [
        'nfdump_all' => 'All Exporters',
    ];
} else {
    $graphs = [
        'nfdump_exporter' => 'Exporter: ' . $vars['exporter'],
    ];
}

foreach ($graphs as $key => $text) {
    $graph_type = $key;
    $graph_array['height'] = '100';
    $graph_array['width'] = '215';
    $graph_array['to'] = \LibreNMS\Config::get('time.now');
    $graph_array['id'] = $app['app_id'];
    $graph_array['type'] = 'application_' . $key;

    if (isset($vars['exporter'])) {
        $graph_array['exporter'] = $vars['exporter'];
    }

    echo '<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">' . $text . '</h3>
    </div>
    <div class="panel-body">
    <div class="row">';
    include 'includes/html/print-graphrow.inc.php';
    echo '</div>';
    echo '</div>';
    echo '</div>';
}
