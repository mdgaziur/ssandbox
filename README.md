# ssandbox

Test with BusyBox(run the command from repository root):

```shell
cargo run -- -e /bin/busybox -r tests/busybox -t 600000 -m 128000000 -f 16000000 -p 10 -c 0 --disable-strict-mode -- sh
```

Here, time limit is set to 600 seconds, memory limit is set to 128 MB, file size limit is set to 16 MB, and the process 
limit is set to 10. The `--disable-strict-mode` flag is used to disable strict mode, which allows the sandboxed process 
to access certain system resources that are normally restricted in strict mode. The command being executed in the 
sandbox is `sh`, which will start a shell within the sandbox environment.

Run `cargo run -- -h` to see all options.
