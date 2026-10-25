use std::process::{Command, Output};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sideeffect"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn help_command_and_flag_show_command_list() {
    for arguments in [&["help"][..], &["--help"][..]] {
        let output = run(arguments);
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("sideeffect help [command [subcommand]]"));
        assert!(text.contains("sideeffect model-preview"));
    }
}

#[test]
fn focused_help_covers_command_and_nested_inventory_topics() {
    let record = run(&["record", "--help"]);
    assert!(record.status.success());
    let record_help = String::from_utf8_lossy(&record.stdout);
    assert!(record_help.contains("current user's permissions"));
    assert!(record_help.contains("not isolation"));

    let startup = run(&["help", "inventory", "startup"]);
    assert!(startup.status.success());
    let startup_help = String::from_utf8_lossy(&startup.stdout);
    assert!(startup_help.contains("configured entry ran"));
    assert!(startup_help.contains("Native Windows startup inventory is planned"));
}

#[test]
fn version_subcommand_matches_version_flag() {
    let command = run(&["version"]);
    let flag = run(&["--version"]);
    assert!(command.status.success());
    assert!(flag.status.success());
    assert_eq!(command.stdout, flag.stdout);
}
