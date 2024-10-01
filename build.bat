@echo on
::cargo clean
::rustup target add x86_64-unknown-linux-gnu
cargo build --release --target=x86_64-pc-windows-msvc
cargo build --release --target=x86_64-pc-windows-gnu
wsl proxychains /root/.cargo/bin/cargo build --release --target=x86_64-unknown-linux-gnu
wsl proxychains /root/.cargo/bin/cargo build --release --target=aarch64-unknown-linux-gnu
::wsl proxychains /root/.cargo/bin/cargo build --release --target=x86_64-linux-android
::wsl proxychains /root/.cargo/bin/cargo build --release --target=aarch64-linux-android