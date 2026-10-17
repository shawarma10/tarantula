# tarantula
CLI Tool for watching networks

## What is this project about?
Tarantula is a simple and easy-to-use CLI tool for watching networks.

It is essentially a wrapper around the [libpcap](https://www.tcpdump.org/) library.

It uses the [etherparse](https://github.com/JulianSchmid/etherparse) crate for parsing network packets.

## Usage
### Cloning & Building
```bash
git clone https://github.com/shawarma10/tarantula
cd tarantula
cargo build -r
```

### Using it
To start it, cd into the directory where the binary is located:
```bash
cd target/release
```

And to run it:
```bash
./tarantula
```

However, you will most likely need root permissions to run it:
```bash
sudo ./tarantula
```
