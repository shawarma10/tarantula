# tarantula
CLI Tool for watching networks

## What is this project about?
Tarantula is a simple and easy-to-use CLI tool for watching networks written in Go.

## Usage
### Cloning & Building
```bash
git clone https://github.com/shawarma10/tarantula
cd tarantula
go build -ldflags="-s -w" -o tarantula cmd/tarantula/main.go
```

### Using it
To run it:
```bash
./tarantula
```

However, you will most likely need root permissions to run it:
```bash
sudo ./tarantula
```

Use the `-h` option to see available options:
```bash
./tarantula -h
```
