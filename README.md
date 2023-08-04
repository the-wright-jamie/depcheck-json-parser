# JSON Parser for OWASP Dependency Checker

## Index

1. [About](#about)
2. [Abilities](#abilities)
3. [How to build](#how-to-build)
4. [Download](#download)

## About

The problem with OWASP's Dependency Checker is that the default HTML output does not tell you if the dependency it's found that has an issue is part of a transitive dependency. This can make actually finding the source of the problem difficult. Telling the dependency checker to output to JSON can provide you with the information on the parent dependency that has a transitive dependency issue (**_for some languages_**, e.g. npm does not provide this information - you'll need to use a dependency tree as a workaround). However, JSON is not very human readable, so this tool was created to help you parse the JSON output and provide you with a list of direct dependencies that have transitive dependency issues.

Originally, this tool was mean to be a part of an automation toolchain for monitoring vulnerable dependencies, however when it came to actually finding those dependencies in the code it was quite difficult as a lot of the time the vulnerable dependency is not a direct dependency but actually a transitive one (and often by a few degrees - e.g. a dependency of a dependency of a dependency). While looking at the JSON output of the scanner, it was discovered that for some packages reference another package. Shortly after, a link was made between this and the transitive dependencies and the tool was then extended to parse and display this information.

## Abilities

- Able to count the number of vulnerable dependencies
- Able to count the number of _total_ vulnerablities that arise from vulnerable dependencies
- Able to list vulnerable dependencies and (if they are a transitive dependency) link the parent dependencies that introduced the package
- Able to output this information to a file which should be easily parsed with a little bit of work and can be used as part of a security monitoring toolchain

## How to build

The project is created with Rust, so to build you need to have Cargo and Rust installed. You can view installation instructions here: <https://www.rust-lang.org/tools/install>

Once installed, all you need to do is run:

```bash
cargo build --release
```

and then navigate to `./target/release` and the executable will be saved under `depcheck-json-parser`.

You can then manually install this onto your shell how you would with any other executable.

## Download

If you'd rather not have to build it from source manually, you can [download the pre-compiled versions from the GitHub releases page](https://github.com/the-wright-jamie/depcheck-json-parser/releases).
