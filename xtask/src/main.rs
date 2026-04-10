//! `cargo xtask` — in-tree build scripts.
//!
//! Pattern borrowed from [`matklad/cargo-xtask`][xtask]. Every task
//! that would normally live in a Makefile or shell script lives here
//! instead, so it's portable, typed, and testable.
//!
//! Commands:
//!
//! - `cargo xtask sample`       regenerate `samples/demo-01.pcap`
//! - `cargo xtask ci`           run the full local CI pipeline
//! - `cargo xtask dist`         build release binaries for the host
//! - `cargo xtask completions`  emit shell completions for every tool
//! - `cargo xtask manpages`     emit man pages for every tool
//!
//! Run `cargo xtask --help` for the canonical list.
//!
//! [xtask]: https://github.com/matklad/cargo-xtask

#![forbid(unsafe_code)]

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "xtask",
    bin_name = "cargo xtask",
    about = "in-tree build scripts for the Airscope workspace"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Regenerate the checked-in sample pcap used by airview/airodump demos.
    Sample,

    /// Run the local equivalent of the CI matrix (fmt + clippy + tests).
    Ci,

    /// Build optimized release binaries for the host target.
    Dist {
        /// Skip the `cargo clean` pass first.
        #[arg(long)]
        no_clean: bool,
    },

    /// Emit shell completions to `dist/completions/`.
    Completions {
        /// Target shell.
        #[arg(long, value_enum, default_value_t = Shell::All)]
        shell: Shell,
    },

    /// Emit man pages to `dist/man/`.
    Manpages,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[allow(clippy::enum_variant_names)] // clap derives kebab-case names, we echo them here
enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
    Elvish,
    All,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let workspace_root = workspace_root()?;
    env::set_current_dir(&workspace_root)
        .with_context(|| format!("chdir {}", workspace_root.display()))?;

    match cli.cmd {
        Cmd::Sample => task_sample(),
        Cmd::Ci => task_ci(),
        Cmd::Dist { no_clean } => task_dist(!no_clean),
        Cmd::Completions { shell } => task_completions(shell, &workspace_root),
        Cmd::Manpages => task_manpages(&workspace_root),
    }
}

// ---------- tasks ----------------------------------------------------------

fn task_sample() -> Result<()> {
    run(&["cargo", "run", "-p", "airscope-wifi", "--example", "make_sample"])
}

fn task_ci() -> Result<()> {
    run(&["cargo", "fmt", "--all", "--", "--check"])?;
    run(&["cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"])?;
    run(&["cargo", "test", "--workspace"])?;
    Ok(())
}

fn task_dist(clean: bool) -> Result<()> {
    if clean {
        run(&["cargo", "clean"])?;
    }
    run(&["cargo", "build", "--workspace", "--release"])?;
    Ok(())
}

fn task_completions(shell: Shell, root: &Path) -> Result<()> {
    let out = root.join("dist").join("completions");
    std::fs::create_dir_all(&out)?;

    let shells: &[clap_complete::Shell] = match shell {
        Shell::Bash => &[clap_complete::Shell::Bash],
        Shell::Zsh => &[clap_complete::Shell::Zsh],
        Shell::Fish => &[clap_complete::Shell::Fish],
        Shell::PowerShell => &[clap_complete::Shell::PowerShell],
        Shell::Elvish => &[clap_complete::Shell::Elvish],
        Shell::All => &[
            clap_complete::Shell::Bash,
            clap_complete::Shell::Zsh,
            clap_complete::Shell::Fish,
            clap_complete::Shell::PowerShell,
            clap_complete::Shell::Elvish,
        ],
    };

    for (name, mut cmd) in clap_trees() {
        for sh in shells {
            let file_name = match sh {
                clap_complete::Shell::Bash => format!("{name}.bash"),
                clap_complete::Shell::Zsh => format!("_{name}"),
                clap_complete::Shell::Fish => format!("{name}.fish"),
                clap_complete::Shell::PowerShell => format!("_{name}.ps1"),
                clap_complete::Shell::Elvish => format!("{name}.elv"),
                _ => format!("{name}.txt"),
            };
            let path = out.join(&file_name);
            let mut file = std::fs::File::create(&path)
                .with_context(|| format!("create {}", path.display()))?;
            clap_complete::generate(*sh, &mut cmd, name.clone(), &mut file);
            eprintln!("wrote {}", path.display());
        }
    }
    Ok(())
}

fn task_manpages(root: &Path) -> Result<()> {
    let out = root.join("dist").join("man");
    std::fs::create_dir_all(&out)?;
    for (name, cmd) in clap_trees() {
        let man = clap_mangen::Man::new(cmd);
        let path = out.join(format!("{name}.1"));
        let mut file =
            std::fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
        man.render(&mut file).with_context(|| format!("render {name}"))?;
        eprintln!("wrote {}", path.display());
    }
    Ok(())
}

// ---------- helpers --------------------------------------------------------

/// Build every CLI tree once so completions and man pages walk the
/// exact same surface the user gets at runtime. We keep minimal local
/// mirrors here rather than importing the binary crates to avoid a
/// circular workspace dependency.
fn clap_trees() -> Vec<(String, clap::Command)> {
    use clap::{Arg, ArgAction, Command as C};
    fn mk(name: &'static str, about: &'static str) -> C {
        C::new(name)
            .about(about)
            .arg(Arg::new("help").short('h').long("help").action(ArgAction::Help))
    }
    vec![
        ("airscope".into(), mk("airscope", "unified TUI launcher for the Airscope suite")),
        ("airmon".into(), mk("airmon", "manage wireless interfaces and monitor mode")),
        ("airodump".into(), mk("airodump", "real-time 802.11 scanner with a TUI")),
        ("aireplay".into(), mk("aireplay", "craft and inject 802.11 management frames")),
        ("airbase".into(), mk("airbase", "broadcast beacons for fake access points")),
        ("airview".into(), mk("airview", "browse a pcap file with an 802.11-aware decoder")),
    ]
}

fn run(argv: &[&str]) -> Result<()> {
    eprintln!("$ {}", argv.join(" "));
    let status = Command::new(argv[0])
        .args(&argv[1..])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("spawn {}", argv.join(" ")))?;
    if !status.success() {
        bail!("{} exited with {status}", argv.join(" "));
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    // `CARGO_MANIFEST_DIR` points at xtask's own Cargo.toml when the
    // binary is built, so its parent is the workspace root.
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("xtask has no parent — is it outside the workspace?"))
}
