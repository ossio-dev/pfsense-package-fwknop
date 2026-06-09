<?php
/*
 * edit.php
 *
 * pfSense fwknop package access rule editor.
 */

require_once("config.inc");
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
	return fwknop_normalize_rule_list(config_get_path(FWKNOP_RULE_PATH, array()));
}

function fwknop_gui_default_rule() {
	return array(
		'enabled' => 'on',
		'description' => '',
		'source_constraint_type' => 'any',
		'source_constraint_value' => '',
		'destination_type' => 'firewall',
		'destination_value' => '',
		'protocol' => 'tcp',
		'destination_port' => '',
		'timeout_seconds' => '30',
		'encryption_key' => '',
		'hmac_key' => '',
		'table_name' => '',
		'ruleid' => ''
	);
}

function fwknop_gui_new_ruleid() {
	if (function_exists('random_bytes')) {
		return 'r' . bin2hex(random_bytes(4));
	}

	return 'r' . dechex(mt_rand());
}

function fwknop_gui_new_key() {
	if (!function_exists('random_bytes')) {
		return base64_encode(openssl_random_pseudo_bytes(32));
	}

	return base64_encode(random_bytes(32));
}

function fwknop_gui_posted_rule($existing) {
	$rule = fwknop_gui_default_rule();
	$rule['enabled'] = isset($_POST['enabled']) ? 'on' : 'off';
	$rule['description'] = trim((string)fwknop_array_get($_POST, 'description', ''));
	$rule['source_constraint_type'] = (string)fwknop_array_get($_POST, 'source_constraint_type', 'any');
	$rule['source_constraint_value'] = trim((string)fwknop_array_get($_POST, 'source_constraint_value', ''));
	$rule['destination_type'] = (string)fwknop_array_get($_POST, 'destination_type', 'firewall');
	$rule['destination_value'] = trim((string)fwknop_array_get($_POST, 'destination_value', ''));
	$rule['protocol'] = strtolower((string)fwknop_array_get($_POST, 'protocol', 'tcp'));
	$rule['destination_port'] = trim((string)fwknop_array_get($_POST, 'destination_port', ''));
	$rule['timeout_seconds'] = trim((string)fwknop_array_get($_POST, 'timeout_seconds', '30'));
	$rule['table_name'] = trim((string)fwknop_array_get($_POST, 'table_name', ''));
	$rule['ruleid'] = trim((string)fwknop_array_get($_POST, 'ruleid', ''));
	$rule['encryption_key'] = trim((string)fwknop_array_get($_POST, 'encryption_key', ''));
	$rule['hmac_key'] = trim((string)fwknop_array_get($_POST, 'hmac_key', ''));

	if ($rule['encryption_key'] === '' && isset($existing['encryption_key'])) {
		$rule['encryption_key'] = $existing['encryption_key'];
	}
	if ($rule['hmac_key'] === '' && isset($existing['hmac_key'])) {
		$rule['hmac_key'] = $existing['hmac_key'];
	}
	if ($rule['ruleid'] === '') {
		$rule['ruleid'] = fwknop_gui_new_ruleid();
	}

	return $rule;
}

function fwknop_gui_key_presence($rule) {
	$encryption = trim((string)fwknop_array_get($rule, 'encryption_key', '')) !== '' ? gettext("present") : gettext("missing");
	$hmac = trim((string)fwknop_array_get($rule, 'hmac_key', '')) !== '' ? gettext("present") : gettext("missing");
	return sprintf(gettext("Saved encryption key: %s. Saved HMAC key: %s."), $encryption, $hmac);
}

if (!empty($_POST['cancel'])) {
	header("Location: index.php");
	exit;
}

$input_errors = array();
$savemsg = '';
$rules = fwknop_gui_access_rules();
$id = null;
$dup = false;

if (isset($_GET['id']) && fwknop_gui_is_numericint($_GET['id'])) {
	$id = (int)$_GET['id'];
}
if (isset($_GET['dup']) && fwknop_gui_is_numericint($_GET['dup'])) {
	$id = (int)$_GET['dup'];
	$dup = true;
}
if (isset($_POST['id']) && fwknop_gui_is_numericint($_POST['id'])) {
	$id = (int)$_POST['id'];
}
if (isset($_POST['dup'])) {
	$dup = true;
}

if ($id !== null && !isset($rules[$id])) {
	$input_errors[] = gettext("Invalid fwknop access rule selected.");
	$id = null;
	$dup = false;
}

$existing = ($id !== null && isset($rules[$id])) ? $rules[$id] : array();
$editing = ($id !== null && !$dup && isset($rules[$id]));
$pconfig = array_replace(fwknop_gui_default_rule(), $existing);
$pconfig['encryption_key'] = '';
$pconfig['hmac_key'] = '';
$generated_keys = false;

if ($_POST) {
	// CSRF: this page uses pfSense guiconfig/Form POST handling and no GET mutations.
	$pconfig = array_replace($pconfig, $_POST);
	$pconfig['enabled'] = isset($_POST['enabled']) ? 'on' : 'off';

	if (isset($_POST['generate_keys'])) {
		$pconfig['encryption_key'] = fwknop_gui_new_key();
		$pconfig['hmac_key'] = fwknop_gui_new_key();
		$generated_keys = true;
		$savemsg = gettext("New base64 keys were generated in the form. Save the rule to store them.");
	} elseif (isset($_POST['save'])) {
		$rule = fwknop_gui_posted_rule($existing);
		fwknop_validate_config(array('accessrule' => array($rule)), $input_errors);

		if (empty($input_errors)) {
			try {
				if ($editing) {
					$rules[$id] = $rule;
				} else {
					$rules[] = $rule;
				}
				config_set_path(FWKNOP_RULE_PATH, array_values($rules));
				write_config(gettext("fwknop access rule saved"));
				fwknop_resync_config();
				header("Location: index.php");
				exit;
			} catch (Throwable $e) {
				$input_errors[] = $e->getMessage();
			}
		}

		$pconfig['encryption_key'] = '';
		$pconfig['hmac_key'] = '';
	}
}

$pgtitle = array(gettext("Services"), gettext("fwknop"), $editing ? gettext("Edit Access Rule") : gettext("Add Access Rule"));
include("head.inc");

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($savemsg != '') {
	print_info_box($savemsg, 'info');
}

fwknop_gui_tabs("keys");

$source_options = array(
	'any' => gettext("ANY"),
	'ip' => gettext("Single IP"),
	'cidr' => gettext("CIDR"),
	'alias' => gettext("Alias")
);
$destination_options = array(
	'firewall' => gettext("Firewall self"),
	'interface' => gettext("Interface address"),
	'host' => gettext("Internal host"),
	'alias' => gettext("Alias")
);
$protocol_options = array(
	'tcp' => gettext("TCP"),
	'udp' => gettext("UDP")
);

$form = new Form(false);
$section = new Form_Section($editing ? gettext("Edit fwknop Access Rule") : gettext("Add fwknop Access Rule"));

$section->addInput(new Form_Checkbox(
	'enabled',
	gettext("Enabled"),
	gettext("Enable this access rule"),
	fwknop_is_enabled($pconfig['enabled'])
));

$section->addInput(new Form_Input(
	'description',
	gettext("Description"),
	'text',
	$pconfig['description']
))->setHelp(gettext("Required. Used in generated comments, labels, and diagnostics."));

$section->addInput(new Form_Select(
	'source_constraint_type',
	gettext("Source Constraint"),
	$pconfig['source_constraint_type'],
	$source_options
))->setHelp(gettext("Use ANY only when the fwknop client source address is not predictable."));

$section->addInput(new Form_Input(
	'source_constraint_value',
	gettext("Source Value"),
	'text',
	$pconfig['source_constraint_value']
))->setHelp(gettext("Leave blank for ANY. Otherwise enter a single IP, CIDR, or safe alias matching the source constraint type."));

$section->addInput(new Form_Select(
	'destination_type',
	gettext("Destination"),
	$pconfig['destination_type'],
	$destination_options
));

$section->addInput(new Form_Input(
	'destination_value',
	gettext("Destination Value"),
	'text',
	$pconfig['destination_value']
))->setHelp(gettext("Leave blank for firewall self. Otherwise enter an interface, host/network, or safe alias matching the destination type."));

$section->addInput(new Form_Select(
	'protocol',
	gettext("Protocol"),
	$pconfig['protocol'],
	$protocol_options
));

$section->addInput(new Form_Input(
	'destination_port',
	gettext("Destination Port"),
	'text',
	$pconfig['destination_port']
))->setHelp(gettext("Enter a TCP/UDP port number or safe port alias."));

$section->addInput(new Form_Input(
	'timeout_seconds',
	gettext("Timeout Seconds"),
	'text',
	$pconfig['timeout_seconds']
))->setHelp(gettext("Temporary PF table entry lifetime requested by fwknopd."));

$section->addInput(new Form_Input(
	'table_name',
	gettext("Generated PF Table"),
	'text',
	$pconfig['table_name']
))->setHelp(gettext("Optional. Leave blank to generate a stable fwknop_ table name from the rule id."));

$section->addInput(new Form_StaticText(
	gettext("Saved Key Status"),
	fwknop_gui_h(fwknop_gui_key_presence($existing))
));

$key_type = $generated_keys ? 'text' : 'password';
$section->addInput(new Form_Input(
	'encryption_key',
	gettext("Encryption Key"),
	$key_type,
	$pconfig['encryption_key']
))->setHelp($editing ? gettext("Base64 key. Leave blank to keep the saved encryption key.") : gettext("Required base64 encryption key."));

$section->addInput(new Form_Input(
	'hmac_key',
	gettext("HMAC Key"),
	$key_type,
	$pconfig['hmac_key']
))->setHelp($editing ? gettext("Base64 key. Leave blank to keep the saved HMAC key.") : gettext("Required base64 HMAC key."));

$btnsave = new Form_Button('save', gettext("Save"), null, 'fa-solid fa-save');
$btnsave->addClass('btn-primary')->addClass('btn-default');
$btngenerate = new Form_Button('generate_keys', gettext("Generate New Keys"), null, 'fa-solid fa-key');
$btngenerate->addClass('btn-warning');
$btncancel = new Form_Button('cancel', gettext("Cancel"));
$btncancel->removeClass('btn-primary')->addClass('btn-default');

$section->addInput(new Form_StaticText(
	null,
	$btnsave . $btngenerate . $btncancel
));

$form->add($section);
$form->addGlobal(new Form_Input('id', 'id', 'hidden', $id));
$form->addGlobal(new Form_Input('ruleid', 'ruleid', 'hidden', $pconfig['ruleid']));
if ($dup) {
	$form->addGlobal(new Form_Input('dup', 'dup', 'hidden', '1'));
}

print($form);
?>

<?=print_info_box(gettext("Saved encryption and HMAC keys are never displayed by default. Generating new keys is a deliberate action and the generated values are shown only until this form is saved or reloaded."), 'info', null)?>

<?php include("foot.inc"); ?>
