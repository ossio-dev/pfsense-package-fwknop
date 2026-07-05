<?php
/*
 * index.php
 *
 * pfSense fwknop package access rule list.
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/fwknop.inc");

function fwknop_gui_h($value) {
	return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function fwknop_gui_is_numericint($value) {
	return function_exists('is_numericint') ? is_numericint($value) : ctype_digit((string)$value);
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

function fwknop_gui_access_rules() {
	return fwknop_get_access_rules();
}

function fwknop_gui_save_access_rules($rules) {
	fwknop_set_access_rules($rules);
	write_config(gettext("fwknop access rules changed"));
	fwknop_resync_config();
}

function fwknop_gui_rule_source($rule) {
	$type = strtoupper((string)fwknop_array_get($rule, 'source_constraint_type', 'any'));
	$value = trim((string)fwknop_array_get($rule, 'source_constraint_value', ''));
	return $value === '' ? $type : "{$type}: {$value}";
}

function fwknop_gui_rule_destination($rule) {
	$type = strtolower((string)fwknop_array_get($rule, 'destination_type', 'firewall'));
	$value = trim((string)fwknop_array_get($rule, 'destination_value', ''));
	if ($type == 'firewall') {
		return gettext("Firewall self");
	}

	return strtoupper($type) . ': ' . $value;
}

function fwknop_gui_key_status($rule) {
	$encryption = trim((string)fwknop_array_get($rule, 'encryption_key', '')) !== '';
	$hmac = trim((string)fwknop_array_get($rule, 'hmac_key', '')) !== '';
	if ($encryption && $hmac) {
		return gettext("Present");
	}
	if (!$encryption && !$hmac) {
		return gettext("Missing");
	}

	return gettext("Partial");
}

$input_errors = array();
$savemsg = '';
$rules = fwknop_gui_access_rules();

if ($_POST && isset($_POST['act'])) {
	// CSRF: pfSense guiconfig/head infrastructure and usepost links protect POST actions.
	if (!isset($_POST['id']) || !fwknop_gui_is_numericint($_POST['id']) || !isset($rules[(int)$_POST['id']])) {
		$input_errors[] = gettext("Invalid fwknop access rule selected.");
	} else {
		$id = (int)$_POST['id'];
		try {
			switch ($_POST['act']) {
				case 'toggle':
					$rules[$id]['enabled'] = fwknop_is_enabled($rules[$id]) ? 'off' : 'on';
					fwknop_gui_save_access_rules($rules);
					$savemsg = gettext("fwknop access rule updated.");
					break;
				case 'delete':
					unset($rules[$id]);
					fwknop_gui_save_access_rules($rules);
					$savemsg = gettext("fwknop access rule deleted.");
					break;
				default:
					$input_errors[] = gettext("Invalid fwknop action.");
					break;
			}
		} catch (Throwable $e) {
			$input_errors[] = $e->getMessage();
		}
	}
}

$pgtitle = array(gettext("Services"), gettext("fwknop"), gettext("Access Rules"));
include("head.inc");

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($savemsg != '') {
	print_info_box($savemsg, 'success');
}

fwknop_gui_tabs("accessrules");
?>

<?=print_info_box(gettext("Single Packet Authorization reduces service exposure but is not a VPN replacement. Keep normal firewall policy restrictive and test access paths before relying on SPA protection."), 'warning', null)?>

<form name="mainform" method="post">
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext("fwknop Access Rules")?></h2></div>
		<div class="panel-body table-responsive">
			<table class="table table-hover table-striped table-condensed">
				<thead>
					<tr>
						<th><?=gettext("Enabled")?></th>
						<th><?=gettext("Description")?></th>
						<th><?=gettext("Source")?></th>
						<th><?=gettext("Destination")?></th>
						<th><?=gettext("Protocol / Port")?></th>
						<th><?=gettext("Timeout")?></th>
						<th><?=gettext("PF Table")?></th>
						<th><?=gettext("Keys")?></th>
						<th><?=gettext("Actions")?></th>
					</tr>
				</thead>
				<tbody>
<?php if (count($rules) > 0): ?>
<?php foreach ($rules as $i => $rule): ?>
					<tr>
						<td><?=fwknop_is_enabled($rule) ? gettext("Yes") : gettext("No")?></td>
						<td><?=fwknop_gui_h(fwknop_array_get($rule, 'description', ''))?></td>
						<td><?=fwknop_gui_h(fwknop_gui_rule_source($rule))?></td>
						<td><?=fwknop_gui_h(fwknop_gui_rule_destination($rule))?></td>
						<td><?=fwknop_gui_h(strtolower((string)fwknop_array_get($rule, 'protocol', 'tcp')) . ' / ' . fwknop_array_get($rule, 'destination_port', ''))?></td>
						<td><?=fwknop_gui_h(fwknop_array_get($rule, 'timeout_seconds', '30'))?></td>
						<td><?=fwknop_gui_h(fwknop_table_name_for_rule($rule, $i))?></td>
						<td><?=fwknop_gui_h(fwknop_gui_key_status($rule))?></td>
						<td>
							<a class="fa-solid fa-pencil" title="<?=gettext("Edit rule")?>" href="edit.php?id=<?=$i?>"></a>
							<a class="fa-regular fa-clone" title="<?=gettext("Copy rule")?>" href="edit.php?dup=<?=$i?>"></a>
							<a class="fa-solid fa-power-off" title="<?=fwknop_is_enabled($rule) ? gettext("Disable rule") : gettext("Enable rule")?>" href="?act=toggle&amp;id=<?=$i?>" usepost></a>
							<a class="fa-solid fa-trash-can text-danger" title="<?=gettext("Delete rule")?>" href="?act=delete&amp;id=<?=$i?>" usepost></a>
						</td>
					</tr>
<?php endforeach; ?>
<?php else: ?>
					<tr>
						<td colspan="9">
							<?php print_info_box(gettext("No fwknop access rules have been configured."), 'info', null); ?>
						</td>
					</tr>
<?php endif; ?>
				</tbody>
			</table>
		</div>
	</div>
	<nav class="action-buttons">
		<a href="edit.php" class="btn btn-success btn-sm">
			<i class="fa-solid fa-plus icon-embed-btn"></i>
			<?=gettext("Add Access Rule")?>
		</a>
		<a href="status.php" class="btn btn-info btn-sm">
			<i class="fa-solid fa-list-check icon-embed-btn"></i>
			<?=gettext("Status / Diagnostics")?>
		</a>
	</nav>
</form>

<?php include("foot.inc"); ?>
