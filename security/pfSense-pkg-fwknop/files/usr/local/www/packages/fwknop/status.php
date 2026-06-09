<?php
/*
 * status.php
 *
 * pfSense fwknop package status and diagnostics.
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/fwknop.inc");

function fwknop_gui_h($value) {
	return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function fwknop_gui_tabs($active) {
	$tab_array = array();
	$tab_array[] = array(gettext("Settings"), $active == "settings", "/pkg_edit.php?xml=fwknop.xml");
	$tab_array[] = array(gettext("Access Rules"), $active == "accessrules", "/packages/fwknop/index.php");
	$tab_array[] = array(gettext("Clients / Keys"), $active == "keys", "/packages/fwknop/edit.php");
	$tab_array[] = array(gettext("Status / Diagnostics"), $active == "status", "/packages/fwknop/status.php");
	$tab_array[] = array(gettext("Advanced Raw Config"), false, "/pkg_edit.php?xml=fwknop.xml");
	display_top_tabs($tab_array);
}

function fwknop_gui_file_status($path) {
	if (!file_exists($path)) {
		return array(
			'state' => gettext("Missing"),
			'size' => '-',
			'mode' => '-',
			'modified' => '-'
		);
	}

	return array(
		'state' => gettext("Present"),
		'size' => filesize($path),
		'mode' => substr(sprintf('%o', fileperms($path)), -4),
		'modified' => date('Y-m-d H:i:s T', filemtime($path))
	);
}

function fwknop_gui_pf_table_entries($table) {
	if (!fwknop_is_valid_table_name($table)) {
		return array('retval' => 1, 'entries' => array(gettext("Invalid table name.")));
	}

	// The table name comes from validated package config, not request parameters.
	$command = '/sbin/pfctl -t ' . escapeshellarg($table) . ' -T show 2>&1';
	$output = array();
	exec($command, $output, $retval);

	return array(
		'retval' => $retval,
		'entries' => array_slice($output, 0, 100)
	);
}

function fwknop_gui_exposure_warnings($rules, $settings) {
	$warnings = array();
	foreach (fwknop_pf_interfaces($settings) as $interface) {
		foreach ($rules as $index => $rule) {
			if (!fwknop_is_enabled(fwknop_array_get($rule, 'enabled', fwknop_array_get($rule, 'enable', 'on')))) {
				continue;
			}
			$protocol = strtolower((string)fwknop_array_get($rule, 'protocol', 'tcp'));
			$port = fwknop_pf_port_for_rule($rule);
			if ($port === '') {
				continue;
			}
			foreach (fwknop_find_exposing_firewall_rules($interface['friendly'], $rule, $protocol, $port) as $rule_descr) {
				$warnings[] = sprintf(
					gettext("Protected service '%s' on %s/%s may already be exposed by normal firewall rule '%s'."),
					fwknop_comment_value((string)fwknop_array_get($rule, 'description', "Rule {$index}")),
					$protocol,
					$port,
					$rule_descr
				);
			}
		}
	}

	return $warnings;
}

$input_errors = array();
$savemsg = '';

if ($_POST && isset($_POST['act'])) {
	// CSRF: pfSense guiconfig/head infrastructure protects these POST-only actions.
	try {
		switch ($_POST['act']) {
			case 'configtest':
				$validation = array();
				$test_post = fwknop_get_settings();
				$test_post['accessrule'] = fwknop_get_access_rules();
				fwknop_validate_config($test_post, $validation);
				if (!empty($validation)) {
					$input_errors = array_merge($input_errors, $validation);
					break;
				}
				fwknop_generate_fwknopd_conf();
				fwknop_generate_access_conf();
				if (function_exists('fwknop_write_table_helper')) {
					fwknop_write_table_helper();
				}
				$savemsg = gettext("Generated fwknop configuration files passed package validation.");
				break;
			case 'resync':
				fwknop_resync_config();
				$savemsg = gettext("fwknop configuration was resynchronized.");
				break;
			case 'restart':
				fwknop_resync_config();
				fwknop_restart();
				$savemsg = gettext("fwknopd restart was requested.");
				break;
			default:
				$input_errors[] = gettext("Invalid fwknop diagnostic action.");
				break;
		}
	} catch (Throwable $e) {
		$input_errors[] = $e->getMessage();
	}
}

$settings = fwknop_get_settings();
$rules = fwknop_get_access_rules();
$service_running = fwknop_service_status();
$file_status = array(
	FWKNOP_FWKNOPD_CONF => fwknop_gui_file_status(FWKNOP_FWKNOPD_CONF),
	FWKNOP_ACCESS_CONF => fwknop_gui_file_status(FWKNOP_ACCESS_CONF),
	FWKNOP_TABLE_HELPER => fwknop_gui_file_status(FWKNOP_TABLE_HELPER)
);
$exposure_warnings = fwknop_gui_exposure_warnings($rules, $settings);

$pgtitle = array(gettext("Services"), gettext("fwknop"), gettext("Status / Diagnostics"));
include("head.inc");

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($savemsg != '') {
	print_info_box($savemsg, 'success');
}

fwknop_gui_tabs("status");
?>

<?=print_info_box(gettext("Single Packet Authorization is not a VPN replacement. It controls when selected services are reachable; it does not encrypt or tunnel the protected traffic."), 'warning', null)?>

<?php foreach ($exposure_warnings as $warning): ?>
	<?=print_info_box(fwknop_gui_h($warning), 'warning', null)?>
<?php endforeach; ?>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext("fwknopd Service")?></h2></div>
	<div class="panel-body">
		<p>
			<strong><?=gettext("Status")?>:</strong>
			<?=($service_running ? gettext("Running") : gettext("Stopped"))?>
		</p>
		<form method="post" name="fwknopactions" id="fwknopactions">
			<button type="submit" name="act" value="configtest" class="btn btn-primary btn-sm">
				<i class="fa-solid fa-list-check icon-embed-btn"></i>
				<?=gettext("Test Config")?>
			</button>
			<button type="submit" name="act" value="resync" class="btn btn-info btn-sm">
				<i class="fa-solid fa-rotate icon-embed-btn"></i>
				<?=gettext("Resync")?>
			</button>
			<button type="submit" name="act" value="restart" class="btn btn-warning btn-sm">
				<i class="fa-solid fa-power-off icon-embed-btn"></i>
				<?=gettext("Restart fwknopd")?>
			</button>
		</form>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext("Generated Files")?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-hover table-striped table-condensed">
			<thead>
				<tr>
					<th><?=gettext("Path")?></th>
					<th><?=gettext("State")?></th>
					<th><?=gettext("Mode")?></th>
					<th><?=gettext("Size")?></th>
					<th><?=gettext("Modified")?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($file_status as $path => $status): ?>
				<tr>
					<td><?=fwknop_gui_h($path)?></td>
					<td><?=fwknop_gui_h($status['state'])?></td>
					<td><?=fwknop_gui_h($status['mode'])?></td>
					<td><?=fwknop_gui_h($status['size'])?></td>
					<td><?=fwknop_gui_h($status['modified'])?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext("PF Tables")?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-hover table-striped table-condensed">
			<thead>
				<tr>
					<th><?=gettext("Rule")?></th>
					<th><?=gettext("Table")?></th>
					<th><?=gettext("Current Entries")?></th>
				</tr>
			</thead>
			<tbody>
<?php if (count($rules) > 0): ?>
<?php foreach ($rules as $i => $rule): ?>
<?php $table = fwknop_table_name_for_rule($rule, $i); ?>
<?php $entries = fwknop_gui_pf_table_entries($table); ?>
				<tr>
					<td><?=fwknop_gui_h(fwknop_array_get($rule, 'description', "Rule {$i}"))?></td>
					<td><?=fwknop_gui_h($table)?></td>
					<td>
<?php if ($entries['retval'] !== 0): ?>
						<span class="text-warning"><?=gettext("Unable to read table entries.")?></span>
<?php endif; ?>
<?php if (empty($entries['entries'])): ?>
						<?=gettext("No entries")?>
<?php else: ?>
						<pre><?=fwknop_gui_h(implode("\n", $entries['entries']))?></pre>
<?php endif; ?>
					</td>
				</tr>
<?php endforeach; ?>
<?php else: ?>
				<tr>
					<td colspan="3"><?php print_info_box(gettext("No fwknop access rules have been configured."), 'info', null); ?></td>
				</tr>
<?php endif; ?>
			</tbody>
		</table>
	</div>
</div>

<?php include("foot.inc"); ?>
