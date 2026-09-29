<?php

$testDir = __DIR__;
$phpBin = PHP_BINARY;
$testFiles = glob($testDir . '/test-*.php') ?: [];
sort($testFiles);

if ($testFiles === []) {
    echo "Geen testbestanden gevonden in {$testDir}." . PHP_EOL;
    exit(0);
}

$totalFailed = 0;

foreach ($testFiles as $file) {
    $name = basename($file);
    echo str_repeat('-', 60) . PHP_EOL;
    echo "Testbestand: {$name}" . PHP_EOL;
    echo str_repeat('-', 60) . PHP_EOL;

    passthru("{$phpBin} " . escapeshellarg($file), $exitCode);
    echo PHP_EOL;

    if ($exitCode !== 0) {
        $totalFailed++;
    }
}

echo str_repeat('=', 60) . PHP_EOL;
echo $totalFailed === 0
    ? 'Alle tests geslaagd.' . PHP_EOL
    : "{$totalFailed} testbestand(en) gefaald." . PHP_EOL;

exit($totalFailed > 0 ? 1 : 0);
